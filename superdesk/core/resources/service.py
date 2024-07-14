# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2024 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license

from typing import (
    Optional,
    Generic,
    TypeVar,
    ClassVar,
    List,
    Dict,
    Any,
    AsyncIterable,
    Union,
    cast,
)
import logging

from bson import ObjectId

from superdesk.errors import SuperdeskApiError
from superdesk.utc import utcnow

from ..app import SuperdeskAsyncApp, get_current_async_app
from .cursor import ElasticsearchResourceCursorAsync, MongoResourceCursorAsync, ResourceCursorAsync, SearchRequest

logger = logging.getLogger(__name__)


ResourceModelType = TypeVar("ResourceModelType", bound="ResourceModel")


class AsyncResourceService(Generic[ResourceModelType]):
    resource_name: ClassVar[str]
    config: "ResourceModelConfig"
    app: SuperdeskAsyncApp

    def __new__(cls):
        app = get_current_async_app()
        try:
            resource_config = app.resources.get_config(cls.resource_name)
        except KeyError:
            raise RuntimeError(f"AsyncResourceService {cls} is not registered with the App")

        instance = getattr(cls, "_instance", None)

        if instance is not None and instance.app != app:
            # The app has changed, need to recreate this service
            # This is only for test purposes when the app is re-created
            instance = None

        if not instance:
            instance = super(AsyncResourceService, cls).__new__(cls)
            instance.app = app
            instance.config = resource_config
            setattr(cls, "_instance", instance)

        return instance

    @property
    def mongo(self):
        """Return instance of MongoCollection for this resource"""

        return self.app.mongo.get_collection_async(self.resource_name)

    @property
    def elastic(self):
        """Returns instance of ``ElasticResourceAsyncClient`` for this resource

        :raises KeyError: If this resource is not configured for Elasticsearch
        """

        return self.app.elastic.get_client_async(self.resource_name)

    def get_model_instance_from_dict(self, data: Dict[str, Any]) -> ResourceModelType:
        """Converts a dictionary to an instance of ``ResourceModel`` for this resource

        :param data: Dictionary to convert
        :return: Instance of ``ResourceModel`` for this resource
        """

        # We can't use ``model_construct`` method to construct instance without validation
        # because nested models are not being converted to model instances
        data.pop("_type", None)
        return cast(ResourceModelType, self.config.data_class.model_validate(data))

    async def find_one(self, **lookup) -> Optional[ResourceModelType]:
        """Find a resource by ID

        :param lookup: Dictionary of key/value pairs used to find the document
        :return: ``None`` if resource not found, otherwise an instance of ``ResourceModel`` for this resource
        """

        try:
            item = await self.elastic.find_one(**lookup)
        except KeyError:
            item = await self.mongo.find_one(**lookup)

        if item is None:
            return None

        return self.get_model_instance_from_dict(item)

    async def find_by_id(self, item_id: Union[str, ObjectId]) -> Optional[ResourceModelType]:
        """Find a resource by ID

        :param item_id: ID of item to find
        :return: ``None`` if resource not found, otherwise an instance of ``ResourceModel`` for this resource
        """

        try:
            item = await self.elastic.find_by_id(item_id)
        except KeyError:
            item = await self.mongo.find_one({"_id": item_id})

        if item is None:
            return None

        return self.get_model_instance_from_dict(item)

    async def search(self, lookup: Dict[str, Any], use_mongo=False) -> ResourceCursorAsync:
        """Search the resource using the provided ``lookup``

        Will use Elasticsearch if configured for this resource and ``use_mongo == False``.

        :param lookup: Dictionary to search
        :param use_mongo: Force to use MongoDB instead of Elasticsearch
        :return: A ``ResourceCursorAsync`` instance with the response
        """

        try:
            if not use_mongo:
                response = await self.elastic.search(lookup)
                return ElasticsearchResourceCursorAsync(self.config.data_class, response)
        except KeyError:
            pass

        response = self.mongo.find(lookup)
        return MongoResourceCursorAsync(self.config.data_class, self.mongo, response, lookup)

    async def on_create(self, docs: List[ResourceModelType]) -> None:
        """Hook to run before creating new resource(s)

        :param docs: List of resources to create
        """

        for doc in docs:
            if doc.created is None:
                doc.created = utcnow()
            if doc.updated is None:
                doc.updated = doc.created

    async def validate_create(self, doc: ResourceModelType):
        """Validate the provided doc for creation

        Runs the async validators

        :param doc: Model instance to validate
        :raises ValueError: If the item is not valid
        """

        await doc.validate_async()

    async def validate_update(self, updates: Dict[str, Any], original: ResourceModelType) -> None:
        """Validate the provided updates dict against the original model instance

        Applies the updates to a copy of the original provided, and runs sync and async validators

        :param updates: Dictionary of updates to be applied
        :param original: Model instance of the original item to be updated
        :raises ValueError: If the item is not valid
        """

        # Construct a new ResourceModelType instance, to allow Pydantic to validate the changes
        # This is not efficient, but will do for now
        updated = original.model_dump(by_alias=True, exclude_unset=True)
        updated.update(updates)
        updated.pop("_type", None)
        # Run the Pydantic sync validators, and get a model instance in return
        model_instance = self.config.data_class.model_validate(updated)

        # Run the async validators
        await model_instance.validate_async()

    async def create(self, docs: List[ResourceModelType]) -> List[str]:
        """Creates a new resource

        Will automatically create the resource(s) in both Elasticsearch (if configured for this resource)
        and MongoDB.

        :param docs: List of resources to create
        :return: List of IDs for the created resources
        """

        await self.on_create(docs)
        ids: List[str] = []
        for doc in docs:
            await self.validate_create(doc)
            doc_dict = doc.model_dump(by_alias=True, exclude_unset=True)
            response = await self.mongo.insert_one(doc_dict)
            ids.append(response.inserted_id)
            try:
                await self.elastic.insert([doc_dict])
            except KeyError:
                pass
        await self.on_created(docs)
        return ids

    async def on_created(self, docs: List[ResourceModelType]) -> None:
        """Hook to run after creating new resource(s)

        :param docs: List of resources that were created
        """

        pass

    async def on_update(self, item_id: str, updates: Dict[str, Any], original: ResourceModelType) -> None:
        """Hook to run before updating a resource

        :param item_id: ID of item to update
        :param updates: Dictionary to update
        :param original: Instance of ``ResourceModel`` for the original resource
        """

        updates.setdefault("_updated", utcnow())

    async def update(self, item_id: str, updates: Dict[str, Any]) -> None:
        """Updates an existing resource

        Will automatically update the resource in both Elasticsearch (if configured for this resource)
        and MongoDB.

        :param item_id: ID of item to update
        :param updates: Dictionary to update
        """

        original = await self.find_by_id(item_id)
        if original is None:
            raise SuperdeskApiError.notFoundError()

        await self.on_update(item_id, updates, original)
        await self.validate_update(updates, original)
        response = await self.mongo.update_one({"_id": item_id}, {"$set": updates})
        try:
            await self.elastic.update(item_id, updates)
        except KeyError:
            pass
        await self.on_updated(updates, original)

    async def on_updated(self, updates: Dict[str, Any], original: ResourceModelType) -> None:
        """Hook to run after a resource has been updated

        :param updates: Dictionary to update
        :param original: Instance of ``ResourceModel`` for the original resource
        """

        pass

    async def on_delete(self, doc: ResourceModelType):
        """Hook to run before deleting a resource

        :param doc: Instance of ``ResourceModel`` for the resource to delete
        """

        pass

    async def delete(self, lookup: Dict[str, Any]) -> List[str]:
        """Deletes resource(s) using a lookup

        :param lookup: Dictionary for the lookup to find items to delete
        :return: List of IDs for the deleted resources
        """

        docs_to_delete = self.mongo.find(lookup).sort("_id", 1)
        ids: List[str] = []

        async for data in docs_to_delete:
            doc = self.get_model_instance_from_dict(data)
            await self.on_delete(doc)
            ids.append(str(doc.id))
            await self.mongo.delete_one({"_id": doc.id})

            try:
                await self.elastic.remove(doc.id)
            except KeyError:
                pass

            await self.on_deleted(doc)
        return ids

    async def on_deleted(self, doc: ResourceModelType):
        """HOok to run after deleting a resource

        :param doc: Instance of ``ResourceModel`` for the resource to delete"""

        pass

    async def get_all(self) -> AsyncIterable[ResourceModelType]:
        """Helper function to get all items from this resource

        :return: An async iterable with ``ResourceModel`` instances
        """

        cursor = self.mongo.find({}).sort("_id")
        async for data in cursor:
            doc = self.get_model_instance_from_dict(data)
            yield doc

    async def get_all_batch(self, size=500, max_iterations=10000, lookup=None) -> AsyncIterable[ResourceModelType]:
        """Helper function to get all items from this resource, in batches

        :param size: Number of items to fetch on each iteration
        :param max_iterations: Maximum number of iterations to run, before returning gracefully
        :param lookup: Optional dictionary used to filter items for
        :return: An async iterable with ``ResourceModel`` instances
        """

        last_id: Optional[Union[str, ObjectId]] = None
        if lookup is None:
            lookup = {}
        _lookup = lookup.copy()
        for i in range(max_iterations):
            if last_id is not None:
                _lookup.update({"_id": {"$gt": last_id}})

            cursor = self.mongo.find(_lookup).sort("_id").limit(size)
            last_doc = None
            async for data in cursor:
                last_doc = data
                doc = self.get_model_instance_from_dict(data)
                last_id = doc.id
                yield doc
            if last_doc is None:
                break
        else:
            logger.warning(f"Not enough iterations for resource {self.resource_name}")

    async def find(self, req: SearchRequest) -> ResourceCursorAsync:
        """Find items from the resource using Elasticsearch

        :param req: A SearchRequest instance with the search params to be used
        :return: An async iterable with ``ResourceModel`` instances
        :raises SuperdeskApiError.notFoundError: If Elasticsearch is not configured
        """

        try:
            cursor, count = await self.elastic.find(req)
            return ElasticsearchResourceCursorAsync(self.config.data_class, cursor.hits)
        except KeyError:
            raise SuperdeskApiError.notFoundError("Elasticsearch not configured for this resource")


from .model import ResourceModelConfig, ResourceModel  # noqa: E402
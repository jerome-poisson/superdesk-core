# -*- coding: utf-8; -*-
#
# This file is part of Superdesk.
#
# Copyright 2024 Sourcefabric z.u. and contributors.
#
# For the full copyright and license information, please see the
# AUTHORS and LICENSE files distributed with this source code, or
# at https://www.sourcefabric.org/superdesk/license

from typing import List, Optional, Any

from pydantic import BaseModel

from superdesk.core.types import SearchRequest
from .types import Endpoint, EndpointGroup, HTTP_METHOD, Request, Response


class ItemRequestViewArgs(BaseModel):
    item_id: str


class RestEndpoints(EndpointGroup):
    """Custom EndpointGroup for REST resources"""

    #: The URL for this resource
    url: str

    #: The list of HTTP methods for the resource endpoints
    resource_methods: List[HTTP_METHOD]

    #: The list of HTTP methods for the resource item endpoints
    item_methods: List[HTTP_METHOD]

    #: Optionally set the route param type for the ID, defaults to ``string``
    id_param_type: str

    def __init__(
        self,
        url: str,
        name: str,
        import_name: Optional[str] = None,
        resource_methods: Optional[List[HTTP_METHOD]] = None,
        item_methods: Optional[List[HTTP_METHOD]] = None,
        id_param_type: Optional[str] = None,
    ):
        super().__init__(name, import_name or __name__)
        self.url = url
        self.resource_methods = resource_methods or ["GET", "POST"]
        self.item_methods = item_methods or ["GET", "PATCH", "DELETE"]
        self.id_param_type = id_param_type or "string"

        resource_url = self.get_resource_url()
        if "GET" in self.resource_methods:
            self.endpoints.append(
                Endpoint(
                    url=resource_url,
                    name="resource_get",
                    func=self.search_items,
                    methods=["GET"],
                )
            )

        if "POST" in self.resource_methods:
            self.endpoints.append(
                Endpoint(
                    url=resource_url,
                    name="resource_post",
                    func=self.create_item,
                    methods=["POST"],
                )
            )

        item_url = self.get_item_url()
        if "GET" in self.item_methods:
            self.endpoints.append(
                Endpoint(
                    url=item_url,
                    name="item_get",
                    func=self.get_item,
                    methods=["GET"],
                )
            )

        if "PATCH" in self.item_methods:
            self.endpoints.append(
                Endpoint(
                    url=item_url,
                    name="item_patch",
                    func=self.update_item,
                    methods=["PATCH"],
                )
            )

        if "DELETE" in self.item_methods:
            self.endpoints.append(
                Endpoint(
                    url=item_url,
                    name="item_delete",
                    func=self.delete_item,
                    methods=["DELETE"],
                )
            )

    def get_resource_url(self) -> str:
        """Returns the URL for this resource, for registering with WSGI"""

        return self.url

    def get_item_url(self, arg_name: str = "item_id") -> str:
        """Returns the URL for an item of this resource, for registering with WSGI

        :param arg_name: The name of the URL argument to use for the resource item URL
        :return: The URL for an item of this resource
        """

        return f"{self.get_resource_url()}/<{self.id_param_type}:{arg_name}>"

    def gen_url_for_item(self, request: Request, item_id: str) -> str:
        """Ge the URL of an item of this resource, for HATEOAS self link

        :param request: The request instance currently being processed
        :param item_id: The ID of the item being returned
        :return: The URL of an item of this resource
        """

        # Import within this method, otherwise a circular import occurs
        from superdesk.core import get_app_config

        # Strip the root URL for the API
        path = request.path.strip("/")
        url_prefix = get_app_config("URL_PREFIX", "")
        if url_prefix:
            url_prefix += "/"
        api_version = get_app_config("API_VERSION")
        if api_version:
            url_prefix += f"{api_version}/"

        if url_prefix and path.startswith(url_prefix):
            path = path[len(url_prefix) :]

        return f"{path}/{item_id}" if request.method == "POST" else path

    async def get_item(
        self,
        args: ItemRequestViewArgs,
        params: Any,
        request: Request,
    ) -> Response:
        """Processes a get single item request"""

        raise NotImplementedError()

    async def create_item(self, request: Request) -> Response:
        """Processes a create item request"""

        raise NotImplementedError()

    async def update_item(
        self,
        args: ItemRequestViewArgs,
        params: None,
        request: Request,
    ) -> Response:
        """Processes an update item request"""

        raise NotImplementedError()

    async def delete_item(self, args: ItemRequestViewArgs, params: None, request: Request) -> Response:
        """Processes a delete item request"""

        raise NotImplementedError()

    async def search_items(
        self,
        args: None,
        params: SearchRequest,
        request: Request,
    ) -> Response:
        """Processes a search request"""

        raise NotImplementedError()

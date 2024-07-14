from typing import Optional, List, Dict
from typing_extensions import Annotated
from enum import Enum

from pydantic import Field

from superdesk.core.module import Module
from superdesk.core.mongo import MongoResourceConfig, MongoIndexOptions
from superdesk.core.elastic.resources import ElasticResourceConfig

from superdesk.core.resources import ResourceModel, ResourceModelConfig, fields, dataclass
from superdesk.core.resources.service import AsyncResourceService
from superdesk.core.resources import validators


@dataclass
class Category:
    qcode: str
    name: str
    scheme: Optional[str] = None


class RelatedItemLinkType(str, Enum):
    text = "text"
    photo = "photo"


@dataclass
class RelatedItems:
    id: Annotated[fields.ObjectId, Field(alias="_id")]
    link_type: Annotated[RelatedItemLinkType, fields.keyword_mapping()]
    slugline: fields.HTML


class MyCustomString(str, fields.CustomStringField):
    elastic_mapping = {"type": "text", "analyzer": "html_field_analyzer"}


class User(ResourceModel):
    first_name: str
    last_name: str
    email: Annotated[
        Optional[str],
        validators.validate_email(),
        validators.validate_iunique_value_async(resource_name="users", field_name="email"),
    ] = None
    name: Optional[fields.TextWithKeyword] = None
    username: Annotated[
        Optional[str],
        validators.validate_unique_value_async(resource_name="users", field_name="username"),
    ] = None
    score: Annotated[
        Optional[int],
        validators.validate_minlength(1),
        validators.validate_maxlength(100),
    ] = None
    bio: Optional[fields.HTML] = None
    code: Optional[fields.Keyword] = None
    categories: Annotated[Optional[List[Category]], fields.nested_list()] = []
    profile_id: Optional[fields.ObjectId] = None
    related_items: Optional[Annotated[List[RelatedItems], fields.nested_list()]] = None
    custom_field: Optional[MyCustomString] = None

    location: Optional[fields.Geopoint] = None

    my_dict: Optional[Dict[str, int]] = None

    created_by: Annotated[
        Optional[str],
        validators.validate_data_relation_async(resource_name="users", external_field="_id"),
    ] = None
    updated_by: Annotated[
        Optional[str],
        validators.validate_data_relation_async(resource_name="users", external_field="_id"),
    ] = None


class UserResourceService(AsyncResourceService[User]):
    pass


user_model_config = ResourceModelConfig(
    name="users",
    data_class=User,
    mongo=MongoResourceConfig(
        indexes=[
            MongoIndexOptions(
                name="users_name_1",
                keys=[("first_name", 1)],
            ),
            MongoIndexOptions(
                name="combined_name_1",
                keys=[("first_name", 1), ("last_name", -1)],
                background=False,
                unique=False,
                sparse=False,
                collation={"locale": "en", "strength": 1},
            ),
        ],
    ),
    elastic=ElasticResourceConfig(),
    service=UserResourceService,
)


module = Module(name="tests.users", resources=[user_model_config])
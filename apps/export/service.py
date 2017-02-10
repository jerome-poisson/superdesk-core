
import logging
from superdesk.services import BaseService
from superdesk import get_resource_service
from superdesk.errors import SuperdeskApiError
from superdesk.publish.formatters import get_all_formatters
from eve.validation import ValidationError
from io import BytesIO
from zipfile import ZipFile
from flask import current_app as app

logger = logging.getLogger(__name__)


class ExportService(BaseService):
    def create(self, docs, **kwargs):
        doc = docs[0]
        formatter = self._validate_and_get_formatter(doc)

        validate = doc.get('validate', False)
        archive_service = get_resource_service('archive')

        unsuccessful_exports = 0
        try:
            in_memory_zip = BytesIO()
            with ZipFile(in_memory_zip, 'a') as zip:
                for item_id in doc.get('item_ids'):
                    item = archive_service.find_one(req=None, _id=item_id)
                    if item:
                        try:
                            if validate:
                                self._validate_for_publish(item)

                            contents = formatter.export(item)
                            zip.writestr(item_id + '.txt', contents.encode("UTF-8"))
                        except:
                            unsuccessful_exports += 1
                    else:
                        unsuccessful_exports += 1

            url = None
            # Store the zip file on media_storage
            # only if at least one item is formatted successfully
            if unsuccessful_exports < len(doc.get('item_ids')):
                zip_id = app.media.put(in_memory_zip.getvalue(), filename='export.zip', content_type='application/zip')
                url = app.media.url_for_download(zip_id, 'application/zip')

            return [{'url': url, 'failures': unsuccessful_exports}]
        except Exception as ex:
            return [{'err_msg': 'Error creating export zip file. Try again please.'}]

    def _validate_for_publish(self, doc):
        """Validates the given story for publish action"""
        validate_item = {'act': 'publish', 'type': doc['type'], 'validate': doc}
        validation_errors = get_resource_service('validate').post([validate_item])
        if validation_errors[0]:
            raise ValidationError(validation_errors)

    def _validate_and_get_formatter(self, doc):
        """Validates incoming request and gets the formatter to be used"""
        if doc.get('item_ids') == 0:
            raise SuperdeskApiError.badRequestError('No items to export.')

        formatter_name = doc.get('format_type')
        formatter = next((f for f in get_all_formatters() if type(f).__name__ == formatter_name), None)
        if not formatter:
            raise SuperdeskApiError.badRequestError('Formatter not found for requested format type.')

        return formatter

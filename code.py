import jwt
import json
from django.http import JsonResponse, HttpResponse
from django.conf import settings

import logging
logger = logging.getLogger(__name__)


def validate_payload(func):
    def wrapper(*args, **kwargs):
        view = args[0]
        request = args[1]
        try:
            payload = json.loads(request.body.decode())
            if request.method == 'POST':
                f = view.form(payload)
                if not f.is_valid():
                    ejson = json.loads(f.errors.as_json())
                    msg = dict([(key, val[0]['message'])
                                for key, val in ejson.items()])
                    return JsonResponse({"error": True, 'msg': msg})
            view.payload = payload
        except json.decoder.JSONDecodeError:
            msg = "Invalid payload format! please check your payload"
            return JsonResponse({'error': True, 'msg': msg})
        return func(*args, **kwargs)
    return wrapper


def new_validate_payload(func):
    def wrapper(*args, **kwargs):
        view = args[0]
        request = args[1]
        try:
            _payload = json.loads(request.body.decode())
            _form = view.form_dict[request.method](_payload)
            if not _form.is_valid():
                ejson = json.loads(_form.errors.as_json())
                msg = dict([(key, val[0]['message'])
                                for key, val in ejson.items()])
                return JsonResponse({"error": True, 'msg': msg})
            else:
                view.payload = _form.cleaned_data
        except json.decoder.JSONDecodeError:
            msg = "Invalid payload format! please check your payload"
            return JsonResponse({'error': True, 'message': msg})
        return func(*args, **kwargs)
    return wrapper


def authenticate(func):
    def wrapper(*args, **kwargs):
        view = args[0]
        request = args[1]
        headers = request.META
        if "HTTP_AUTHORIZATION" not in headers:
            return HttpResponse(403)
        token = headers["HTTP_AUTHORIZATION"].split()[1]
        user = headers.get("HTTP_X_USER", None)
        guid = headers.get("HTTP_X_GUID", None)
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
            view.uid = payload["uid"]
            view.account = payload["account"]
            view.user = user
            view.guid = guid
        except jwt.exceptions.InvalidSignatureError:
            return HttpResponse("Invalid Token", status=401)
        return func(*args, **kwargs)
        # try:
        #     return func(*args, **kwargs)
        # except Exception as e:
        #     err_str = str(e)
        #     logger.debug(err_str)
        #     print(err_str)
        #     return HttpResponse(err_str, status=500)
    return wrapper

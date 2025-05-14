import json
import uuid
from django.core.serializers.json import DjangoJSONEncoder


class UUIDEncoder(DjangoJSONEncoder):
    """
    Custom JSON encoder that handles UUID objects.
    
    This encoder extends Django's JSONEncoder to properly serialize UUID objects
    by converting them to strings, making them JSON-serializable.
    """
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            # Convert UUID objects to strings
            return str(obj)
        return super().default(obj)


def dumps(obj, **kwargs):
    """
    Serialize obj to a JSON formatted string using the UUIDEncoder.
    
    Args:
        obj: The object to serialize to JSON
        **kwargs: Additional keyword arguments to pass to json.dumps()
        
    Returns:
        str: A JSON formatted string
    """
    kwargs.setdefault('cls', UUIDEncoder)
    return json.dumps(obj, **kwargs)
from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    """Retourne dictionary[key] ou None."""
    return dictionary.get(key)

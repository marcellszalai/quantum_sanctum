# frontend/templatetags/custom_tags.py

from django import template

register = template.Library()

@register.filter
def get_item(list, index):
    """
    Retrieves an item from a list by its index.
    """
    try:
        return list[index]
    except IndexError:
        return ''
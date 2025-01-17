import markdown
import bleach

allowed_tags = list(bleach.ALLOWED_TAGS) + [
    'p', 'strong', 'em', 'u', 's', 'del', 'mark', 
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 
    'pre', 'code', 'ul', 'ol', 'li', 'a', 'img'
]

allowed_attributes = {
    **bleach.ALLOWED_ATTRIBUTES,
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title'],
    'code': ['class']
}

allowed_protocols = ['http', 'https', 'mailto'] 

def markdown_to_safe_html(markdown_text):
    html_content = markdown.markdown(markdown_text, extensions=['extra', 'codehilite', 'nl2br'])

    safe_html = bleach.clean(
        html_content, 
        tags=allowed_tags, 
        attributes=allowed_attributes, 
        protocols=allowed_protocols
    )

    return safe_html

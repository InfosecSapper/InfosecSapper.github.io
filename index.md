---
layout: default
title: Home
---

# InfosecSapper

Security research, system behaviour, attack paths, adversary tradecraft and defensive investigations.

## Knowledge Base

{% for collection in site.collections %}

{% unless collection.label == "posts" %}

### {{ collection.metadata.title }}

{{ collection.metadata.description }}

({{ collection.docs.size }} articles)

<ul>
{% for doc in collection.docs %}
    <li>
        {{ doc.url }}
    </li>
{% endfor %}
</ul>

{% endunless %}
{% endfor %}

## Legacy Articles

<ul>
{% for post in site.posts %}
    <li>
        {{ post.url }}{{ post.title }}</a>
    </li>
{% endfor %}
</ul>
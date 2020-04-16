# -*- coding: utf-8 -*-
from django.dispatch import Signal


user_accept_consent = Signal(providing_args=['user', 'client', 'scope'])
user_decline_consent = Signal(providing_args=['user', 'client', 'scope'])

code_created = Signal(providing_args=["code", "user", "request"])
token_created = Signal(
    providing_args=["token", "grant_type", "code", "refresh_token", "user", "request"]
)

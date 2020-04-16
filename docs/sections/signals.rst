.. _signals:

Signals
#######

Use signals in your application to get notified when some actions occur.

For example::

    from django.dispatch import receiver

    from oidc_provider.signals import user_decline_consent


    @receiver(user_decline_consent)
    def my_callback(sender, **kwargs):
        print(kwargs)
        print('Ups! Some user has declined the consent.')

user_accept_consent
===================

Sent when a user accept the authorization page for some client.

user_decline_consent
====================

Sent when a user decline the authorization page for some client.


code_created
=============================

Sent whenever a new code object is issued.

Receives the following arguments:

* ``code``: The ``oidc_provider.models.Code`` object that's been created.

* ``user``: ``DJANGO_AUTH_USER_MODEL`` The user this code was issued for.

* ``request``: Django request object wwhere this code was issued.


token_created
=============================

Sent whenever a new token is issued.

Receives the following arguments:

* ``token``: The ``oidc_provider.models.Token`` object being checked.

* ``grant_type``: ``string`` The grant_type used to authorize this token creation. This usally matches the OIDC grant type. In the specific case of a token issued during a token login flow the value is ``token_flow``

* ``code``: ``oidc_provider.models.Code`` Code object used to authroize creation if ``grant_type`` is ``authrization_code``

* ``refresh_token``: ``oidc_provider.models.Token`` The token object that was used to authroize creation if ``grant_type`` is ``refresh_token``

* ``user``: ``DJANGO_AUTH_USER_MODEL`` The user this token was issued for.

* ``request``: Django request object wwhere this token was issued.
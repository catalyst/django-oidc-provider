Stability Policy
================

This document outlines what changes are considered breaking, and which are implementation details that could be changed.

django-oidc-provider follows semantic versioning, breaking changes will only be made in MAJOR releases.

Security
--------

As an exception to **all** rules listed below security issues which require breaking changes may be made in MINOR and PATCH releases.

Endpoints
---------

We guarantee that endpoints will:

* Have stable URLs

* Have a stable content type

* Not remove fields from responses

* Not change the type of fields in responses

* Not add required fields in requests

We reserve the right to:

* Add optional request fields

* Add response fields

* Add headers

Settings
--------

We guarantee that settings will:

* Not be renamed

* Not change type

* Not change their default value (for existing deployments only)

We reserve the right to:

* Add new settings

Hooks
-----

We guarantee that hooks will:

* Not constrain the return type

* Be passed the same number, and type, of positional arguments

* Be passed keyword arguments with the same name, and type

We reserve the right to:

* Add additional keyword arguments
* Accept additional return types
* Add fields to types passed as positional/keyword arguments

Imports
-------

We guarantee the stability (names, parameter types, return types, field values) of imports from ``oidc_provider.public.*``.
Any imports from other modules are **considered unstable** and **may be changed in MINOR or PATCH releases**.

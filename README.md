# CAS3 Client for Liferay6 with ClearPass and Proxy Ticket Support

## Introduction

Liferay6 supports CAS out-of-the-box but without support for CAS ClearPass or Proxy Tickets.
This package fixes that.

## Dependencies

* Liferay CE 6.x
* Liferay CE 6.x plugins SDK
* CAS Server 3.x optionally with ClearPass support

## Deployment

1. Install Liferay CE 6.x plugins SDK and make sure build.{username}.properties points to your deployment
2. Under ext/ mkdir cas3-ext/ and places this package there
3. Start up liferay
4. cd cas3-ext; ant clean deploy
5. Login into liferay and using the Control Panel and makes these changes:

`liferay contro planel > settings > authentication > General:
* How do users authenticate? change to By Screen Name

liferay contro planel > settings > authentication > CAS:
* enabled  checked
* Login URL: https://cas.example.org:8443/cas/login
* Logout URL: https://cas.example.org:8443/cas/logout
* Server Name: portal.example.org:8443 
* Server URL: https://cas.example.org:8443/cas 
`

6. edit ROOT/WEB-INF/web.xml and comment out the stock SSO filters

7. Restart Liferay

Clicking on login should take you to the CAS login screen.

## Notes
For this to work you need to have a properly configured CAS server with ClearPass enabled and both services must be running over SSL.
You may also need to edit web.xml and properties-ext.xml to have the right CAS and portal URLs.

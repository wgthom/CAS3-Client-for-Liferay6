package com.liferay.portal.security.auth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.portlet.PortletSession;

public class CasAssertionUtil {
	
	
	/**
	 * return proxy ticket from CAS for the url (service) given 
	 * @param service : the url of the service to authorize 
	 * @param portletSession : the portletSession 
	 * @return The String proxy ticket
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws IllegalArgumentException
	 * @throws IllegalAccessException
	 * @throws InvocationTargetException
	 */
	@SuppressWarnings("rawtypes")
    public static String getProxyTicketForService(String service, PortletSession portletSession) throws SecurityException, NoSuchMethodException, IllegalArgumentException, IllegalAccessException, InvocationTargetException{
	    Object assertionObject = (Object)portletSession.getAttribute("LIFERAY_SHARED_CAS_ASSERTION",PortletSession.APPLICATION_SCOPE);
		if (assertionObject != null){
			Method getPrincipalMethod = assertionObject.getClass().getMethod("getPrincipal", null);
			Object principalObject = getPrincipalMethod.invoke(assertionObject, null);
			Class partypes[] = new Class[1];
	        partypes[0] = new String().getClass();
			Method getProxyTicketForMethod = principalObject.getClass().getMethod("getProxyTicketFor", partypes);
			Object arglist[] = new Object[1];
	        arglist[0] = new String(service);
			Object proxyTicketObject = getProxyTicketForMethod.invoke(principalObject, arglist);
			if (proxyTicketObject!=null & proxyTicketObject instanceof String){
				return (String)proxyTicketObject;
			}
		}
		return null;
	}

}

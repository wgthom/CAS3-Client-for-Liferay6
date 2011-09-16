/**
 * Copyright (c) 2000-2011 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.security.auth;

import java.net.URLEncoder;

import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.*;
import com.liferay.portal.model.CompanyConstants;
import com.liferay.portal.model.User;
import com.liferay.portal.security.ldap.LDAPSettingsUtil;
import com.liferay.portal.security.ldap.PortalLDAPImporterUtil;
import com.liferay.portal.security.ldap.PortalLDAPUtil;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.servlet.filters.sso.cas.CASFilter;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;

import javax.naming.Binding;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Properties;

import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.XmlUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter;

/**
 * @author Brian Wing Shun Chan                 `
 * @author Jorge Ferrer
 * @author Wesley Gong
 * @author Daeyoung Song
 * @author William G. Thompson, Jr.
 */
public class CAS3AutoLogin implements AutoLogin {

    public final static String CONST_CAS_ASSERTION = "_const_cas_assertion_";

	public String[] login(
		HttpServletRequest request, HttpServletResponse response) {

		String[] credentials = null;

		try {
			long companyId = PortalUtil.getCompanyId(request);

			if (!PrefsPropsUtil.getBoolean(
					companyId, PropsKeys.CAS_AUTH_ENABLED,
					PropsValues.CAS_AUTH_ENABLED)) {

				return credentials;
			}

			HttpSession session = request.getSession();

            // Get principal name directly from CAS Assertion instead of via Liferay CASFilter)
            // String login = (String)session.getAttribute(CASFilter.LOGIN);
            Assertion assertion = null;
            String login = null;
            if (session.getAttribute(CONST_CAS_ASSERTION) != null) {
                assertion = (Assertion) session.getAttribute(CONST_CAS_ASSERTION);
                login = assertion.getPrincipal().getName();
            }

			if (Validator.isNull(login)) {
				return credentials;
			}

			String authType = PrefsPropsUtil.getString(
				companyId, PropsKeys.COMPANY_SECURITY_AUTH_TYPE,
				PropsValues.COMPANY_SECURITY_AUTH_TYPE);

			User user = null;

			if (PrefsPropsUtil.getBoolean(
					companyId, PropsKeys.CAS_IMPORT_FROM_LDAP,
					PropsValues.CAS_IMPORT_FROM_LDAP)) {

				try {
					if (authType.equals(CompanyConstants.AUTH_TYPE_SN)) {
						user = importLDAPUser(
							companyId, StringPool.BLANK, login);
					}
					else {
						user = importLDAPUser(
							companyId, login, StringPool.BLANK);
					}
				}
				catch (SystemException se) {
				}
			}

			if (user == null) {
				if (authType.equals(CompanyConstants.AUTH_TYPE_SN)) {
					user = UserLocalServiceUtil.getUserByScreenName(
						companyId, login);
				}
				else {
					user = UserLocalServiceUtil.getUserByEmailAddress(
						companyId, login);
				}
			}

			String redirect = ParamUtil.getString(request, "redirect");

			if (Validator.isNotNull(redirect)) {
				request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirect);
			}

            credentials = new String[3];

            credentials[0] = String.valueOf(user.getUserId());

            // check for ClearPass enabled
            if (PrefsPropsUtil.getBoolean(companyId, PropsKeys.CAS_CLEARPASS_ENABLED, PropsValues.CAS_CLEARPASS_ENABLED)) {
                // CAS3AutoLogin is fired on every request, so we need to check if we've already got the password
                if (session.getAttribute("CAS_CLEARPASS") == null) {
                    session.setAttribute("CAS_CLEARPASS", CAS3AutoLogin.getClearTextPassword(assertion, companyId));
                }
                credentials[1] = (String) session.getAttribute("CAS_CLEARPASS");
                credentials[2] = Boolean.FALSE.toString(); // password encrypted? nope.
            } else {
                credentials[1] = user.getPassword();
                credentials[2] = Boolean.TRUE.toString();
            }

			return credentials;
		}
		catch (Exception e) {
			_log.error(e, e);
		}

		return credentials;
	}


    private static String getClearTextPassword(Assertion assertion, Long companyId) {

        String clearPassUrl;
        try {
                clearPassUrl = PrefsPropsUtil.getString(companyId, PropsKeys.CAS_CLEARPASS_URL, PropsValues.CAS_CLEARPASS_URL);
            } catch (SystemException e) {
                throw new RuntimeException(e);
        }
        final String proxyTicket = assertion.getPrincipal().getProxyTicketFor(clearPassUrl);
        final String clearPassRequestUrl = clearPassUrl + "?" + "ticket=" + proxyTicket + "&" + "service=" + URLEncoder.encode(clearPassUrl);
        final String response = CommonUtils.getResponseFromServer(clearPassRequestUrl);
        final String password = XmlUtils.getTextForElement(response, "credentials");

        return password;
    }


	/**
	 * @deprecated Use <code>importLDAPUser</code>.
	 */
	protected User addUser(long companyId, String screenName) throws Exception {
		return importLDAPUser(companyId, StringPool.BLANK, screenName);
	}

	protected User importLDAPUser(
			long ldapServerId, long companyId, String emailAddress,
			String screenName)
		throws Exception {

		LdapContext ldapContext = null;

		try {
			String postfix = LDAPSettingsUtil.getPropertyPostfix(ldapServerId);

			String baseDN = PrefsPropsUtil.getString(
				companyId, PropsKeys.LDAP_BASE_DN + postfix);

			ldapContext = PortalLDAPUtil.getContext(ldapServerId, companyId);

			if (ldapContext == null) {
				throw new SystemException("Failed to bind to the LDAP server");
			}

			String filter = PrefsPropsUtil.getString(
				companyId, PropsKeys.LDAP_AUTH_SEARCH_FILTER + postfix);

			if (_log.isDebugEnabled()) {
				_log.debug("Search filter before transformation " + filter);
			}

			filter = StringUtil.replace(
				filter,
				new String[] {
					"@company_id@", "@email_address@", "@screen_name@"
				},
				new String[] {
					String.valueOf(companyId), emailAddress, screenName
				});

			if (_log.isDebugEnabled()) {
				_log.debug("Search filter after transformation " + filter);
			}

			Properties userMappings = LDAPSettingsUtil.getUserMappings(
				ldapServerId, companyId);

			String userMappingsScreenName = GetterUtil.getString(
				userMappings.getProperty("screenName")).toLowerCase();

			SearchControls searchControls = new SearchControls(
				SearchControls.SUBTREE_SCOPE, 1, 0,
				new String[] {userMappingsScreenName}, false, false);

			NamingEnumeration<SearchResult> enu = ldapContext.search(
				baseDN, filter, searchControls);

			if (enu.hasMoreElements()) {
				if (_log.isDebugEnabled()) {
					_log.debug("Search filter returned at least one result");
				}

				Binding binding = enu.nextElement();

				Attributes attributes = PortalLDAPUtil.getUserAttributes(
					ldapServerId, companyId, ldapContext,
					PortalLDAPUtil.getNameInNamespace(
						ldapServerId, companyId, binding));

				return PortalLDAPImporterUtil.importLDAPUser(
					ldapServerId, companyId, ldapContext, attributes,
					StringPool.BLANK);
			}
			else {
				return null;
			}
		}
		catch (Exception e) {
			if (_log.isWarnEnabled()) {
				_log.warn("Problem accessing LDAP server " + e.getMessage());
			}

			if (_log.isDebugEnabled()) {
				_log.debug(e, e);
			}

			throw new SystemException(
				"Problem accessing LDAP server " + e.getMessage());
		}
		finally {
			if (ldapContext != null) {
				ldapContext.close();
			}
		}
	}

	protected User importLDAPUser(
			long companyId, String emailAddress, String screenName)
		throws Exception {

		long[] ldapServerIds = StringUtil.split(
			PrefsPropsUtil.getString(companyId, "ldap.server.ids"), 0L);

		if (ldapServerIds.length <= 0) {
			ldapServerIds = new long[] {0};
		}

		for (long ldapServerId : ldapServerIds) {
			User user = importLDAPUser(
				ldapServerId, companyId, emailAddress, screenName);

			if (user != null) {
				return user;
			}
		}

		if (_log.isDebugEnabled()) {
			if (Validator.isNotNull(emailAddress)) {
				_log.debug(
					"User with the email address " + emailAddress +
						" was not found in any LDAP servers");
			}
			else {
				_log.debug(
					"User with the screen name " + screenName +
						" was not found in any LDAP servers");
			}
		}

		return null;
	}

	private static Log _log = LogFactoryUtil.getLog(CAS3AutoLogin.class);

}
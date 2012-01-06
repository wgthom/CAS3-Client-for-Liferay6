package com.liferay.portal.servlet.filters.sso.cas;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;

import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;
/**
 * Filter implementation to intercept all requests and attempt to authenticate
 * the user by redirecting them to CAS (unless the user has a ticket).
 * <p>
 * This filter allows you to specify the following parameters (in parameter system of liferay):
 * <ul>
 * <li><code>casServerLoginUrl</code> - the url to log into CAS, i.e. https://cas.rutgers.edu/login</li>
 * <li><code>renew</code> - true/false on whether to use renew or not.</li>
 * <li><code>gateway</code> - true/false on whether to use gateway or not.</li>
 * </ul>
 *
 * <p>Please see AbstractCasFilter for additional properties.</p>
 *
 * @author Christophe Mourette
 */
public class CasAuthenticationFilter extends AbstractCasFilter {

    /**
     * The URL to the CAS Server login.
     */
    private String casServerLoginUrl;

    /**
     * Whether to send the renew request or not.
     */
    private boolean renew = false;

    /**
     * Whether to send the gateway request or not.
     */
    private boolean gateway = false;
    
    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();
    
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
        super.initInternal(filterConfig);
        try {
            setCasServerLoginUrl(PrefsPropsUtil.getString(PropsKeys.CAS_LOGIN_URL, PropsValues.CAS_LOGIN_URL));
            setServerName(PrefsPropsUtil.getString(PropsKeys.CAS_SERVER_NAME, PropsValues.CAS_SERVER_NAME));
        } catch (SystemException e) {
            log.error("error in initInternal() while getting parameter from properties", e);
        }
        setRenew(parseBoolean(getPropertyFromInitParams(filterConfig, "renew", "false")));
        log.trace("Loaded renew parameter: " + this.renew);
        setGateway(parseBoolean(getPropertyFromInitParams(filterConfig, "gateway", "false")));
        log.trace("Loaded gateway parameter: " + this.gateway);
        final String gatewayStorageClass = getPropertyFromInitParams(filterConfig, "gatewayStorageClass", null);
        if (gatewayStorageClass != null) {
            try {
                this.gatewayStorage = (GatewayResolver) Class.forName(gatewayStorageClass).newInstance();
            } catch (final Exception e) {
                log.error(e,e);
                throw new ServletException(e);
            }
        }

    }
    
    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
    }


    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException,
            ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        long companyId = PortalUtil.getCompanyId(request);
        boolean casEnabled = false;
        try {
            casEnabled = PrefsPropsUtil.getBoolean(companyId, PropsKeys.CAS_AUTH_ENABLED, PropsValues.CAS_AUTH_ENABLED);
        } catch (SystemException e) {
            log.error("error in initInternal() while getting parameter from properties", e);
        }
        if (casEnabled) {
            
            
            final HttpSession session = request.getSession(false);
            
            

            String pathInfo = request.getPathInfo();

            if (pathInfo.indexOf("/portal/logout") != -1) {
                session.invalidate();

                String logoutUrl= pathInfo;
                try {
                    logoutUrl = PrefsPropsUtil.getString(
                        companyId, PropsKeys.CAS_LOGOUT_URL,
                        PropsValues.CAS_LOGOUT_URL);
                } catch (SystemException e) {
                    log.error("error while reading properties", e);
                }

                response.sendRedirect(logoutUrl);

                return;
            }
            
            final String serviceUrl = constructServiceUrl(request, response);
            final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;
    
            if (assertion != null) {
                filterChain.doFilter(request, response);
                return;
            }
    
            final String ticket = CommonUtils.safeGetParameter(request, getArtifactParameterName());
            final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);
    
            if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
                filterChain.doFilter(request, response);
                return;
            }
    
            final String modifiedServiceUrl;
    
            log.debug("no ticket and no assertion found");
            if (this.gateway) {
                log.debug("setting gateway attribute in session");
                modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
            } else {
                modifiedServiceUrl = serviceUrl;
            }
    
            if (log.isDebugEnabled()) {
                log.debug("Constructed service url: " + modifiedServiceUrl);
            }
    
            final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, getServiceParameterName(), modifiedServiceUrl, this.renew,
                    this.gateway);
    
            if (log.isDebugEnabled()) {
                log.debug("redirecting to \"" + urlToRedirectTo + "\"");
            }
    
            response.sendRedirect(urlToRedirectTo);
        } else {
            final HttpSession session = request.getSession(false);
            String pathInfo = request.getPathInfo();
            if (pathInfo.indexOf("/portal/logout") != -1) {
                session.invalidate();
                response.sendRedirect("/");
                return;
            }
            filterChain.doFilter(request, response);
        }
    }
    
    public final void setRenew(final boolean renew) {
        this.renew = renew;
    }

    public final void setGateway(final boolean gateway) {
        this.gateway = gateway;
    }

    public final void setCasServerLoginUrl(final String casServerLoginUrl) {
        this.casServerLoginUrl = casServerLoginUrl;
    }
    
    public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
        this.gatewayStorage = gatewayStorage;
    }

}

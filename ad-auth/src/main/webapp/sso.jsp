<%@page import="java.io.IOException"%>
<%@page import="java.net.URL"%>
<%@page import="java.net.URLDecoder"%>
<%@page import="java.security.PrivilegedAction"%>

<%@page import="javax.security.auth.Subject"%>
<%@page import="javax.security.auth.callback.Callback"%>
<%@page import="javax.security.auth.callback.CallbackHandler"%>
<%@page import="javax.security.auth.callback.NameCallback"%>
<%@page import="javax.security.auth.callback.PasswordCallback"%>
<%@page import="javax.security.auth.callback.UnsupportedCallbackException"%>
<%@page import="javax.security.auth.login.LoginContext"%>
<%@page import="javax.security.auth.login.LoginException"%>

<%@page import="org.ietf.jgss.GSSContext"%>
<%@page import="org.ietf.jgss.GSSCredential"%>
<%@page import="org.ietf.jgss.GSSException"%>
<%@page import="org.ietf.jgss.GSSManager"%>
<%@page import="org.ietf.jgss.Oid"%>
<%@page import="sun.misc.BASE64Decoder"%>


<%!private static final String ACTIVE_DIRECTORY_SERVER = "127.0.0.1";
	private static final String DEAULT_DOMAIN = "JAVA.SUN.COM";
	private static final String SP_PASSWORD = "Password";
	private static final String JAAS_CONF = "src/main/resources/jaas.conf";
	
	static {
		System.setProperty("com.ibm.security.jgss.debug", "all");
		System.setProperty("com.ibm.security.krb5.Krb5Debug", "all");
	}
%>

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%
	String auth = request.getHeader("Authorization");
	String clientName = "";
	if (auth == null) {
		response.reset();
		response.setHeader("WWW-Authenticate", "NEGOTIATE");
		response.setContentLength(0);
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.flushBuffer();
		return;
	} else {
		clientName = authenticate(auth);
	}
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>SSO Test</title>
</head>
<body>
	The client name is:
	<%=clientName%>
</body>
</html>


<%!private static final String LOGIN_MODULE_NAME = "SSOTESTING";

	static {
		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("java.security.krb5.realm", DEAULT_DOMAIN);
		System.setProperty("java.security.krb5.kdc", ACTIVE_DIRECTORY_SERVER);
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
		System.setProperty("java.security.auth.login.config", JAAS_CONF);
	}

	/**
	 * Authenticates the given kerberos token and returns the client principal
	 */
	public static String authenticate(String argKerberosTokenAsBase64) throws Exception {
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] kerberosToken = decoder.decodeBuffer(argKerberosTokenAsBase64.substring("Negotiate ".length()));
		String clientName = null;
		try {
			// Login to the KDC and obtain subject for the service principal
			Subject subject = createServiceSubject(SP_PASSWORD);
			if (subject != null) {
				clientName = acceptSecurityContext(subject, kerberosToken).toUpperCase();
				System.out.println("Security context successfully initialised!");
			} else {
				throw new Exception("Unable to obtain kerberos service context");
			}
		} catch (Throwable throwable) {
			System.out.println("Token: " + argKerberosTokenAsBase64);
			throwable.printStackTrace();
			throw new Exception(throwable);
		}
		return clientName;
	}

	/**
	 * Creates service subject based on the service principal and service
	 * password
	 */
	private static Subject createServiceSubject(String password) throws LoginException {
		// "Client" references the JAAS configuration in the jaas.conf file.
		LoginContext loginCtx = new LoginContext(LOGIN_MODULE_NAME, new LoginCallbackHandler(password));
		loginCtx.login();
		return loginCtx.getSubject();
	}

	/**
	 * Completes the security context initialisation and returns the client
	 * name.
	 */
	private static String acceptSecurityContext(Subject argSubject, final byte[] serviceTicket) throws GSSException {
		// Accept the context and return the client principal name.
		return (String) Subject.doAs(argSubject, new PrivilegedAction() {
			public Object run() {
				try {
					// Identify the server that communications are being made
					// to.
					GSSManager manager = GSSManager.getInstance();
					GSSCredential serverCreds = null;
					if ("IBM Corporation".equalsIgnoreCase(System.getProperty("java.vendor"))) {
						Oid oid = new Oid("1.3.6.1.5.5.2"); // SPNEGO
						serverCreds = manager.createCredential(null, 10000, oid, GSSCredential.ACCEPT_ONLY);
					}
					GSSContext context = manager.createContext(serverCreds);
					context.acceptSecContext(serviceTicket, 0, serviceTicket.length);
					return context.getSrcName().toString();
				} catch (GSSException exp) {
					throw new RuntimeException(exp);
				}
			}
		});
	}

	/**
	 * Returns the path of the given classpath resource.
	 */
	private static String findResourcePath(String resource) {
		try {
			URL url = Thread.currentThread().getContextClassLoader().getResource(resource);
			if (url != null) {
				return URLDecoder.decode(url.toString());
			}
		} catch (Throwable ex) {
			throw new RuntimeException("Unable to find request resource: " + resource, null);
		}
		return null;
	}

	private static class LoginCallbackHandler implements CallbackHandler {

		private String password;
		private String username;

		public LoginCallbackHandler() {
			super();
		}

		public LoginCallbackHandler(String name, String password) {
			super();
			this.username = name;
			this.password = password;
		}

		public LoginCallbackHandler(String password) {
			super();
			this.password = password;
		}

		/**
		 * Handles the callbacks, and sets the user/password detail.
		 */
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback && username != null) {
					NameCallback nc = (NameCallback) callbacks[i];
					nc.setName(username);
				} else if (callbacks[i] instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callbacks[i];
					pc.setPassword(password.toCharArray());
				} else {
					throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
				}
			}
		}
	}%>
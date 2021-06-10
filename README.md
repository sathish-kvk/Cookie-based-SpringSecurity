# Cookie-based-SpringSecurity

If you need authentication (and authorization) within your Spring Boot web application, the natural choice is to use Spring Security. It’s easy to use (just add the spring-boot-starter-security and there you go) and, as long as you stick close to the defaults, it’s also quite easy to configure. But, by sticking to those defaults, you will automatically get a session that is persisted on the server-side (in memory, as long as you do not specify otherwise). That’s a problem if you want to run multiple instances of your application. And, additionally, it’s not necessary, at least in most cases. There’s another mechanism for keeping some user session state in a web application. It’s called Cookie. And, instead of using it only to store a session identifier, why not let it hold the data itself. This blog post shows, that, with some effort, it’s possible to configure Spring Security to store its session information in a cookie instead of a server-side session.

## Spring Security architecture
Spring Security integrates into Spring web as a servlet request filter (see Chapter 9 of the Spring Security Reference). The FilterChainProxy is the central filter class and contains a parallel SecurityFilterChain (see Chapter 9.4 of the Spring Security Reference). The FilterChainProxy is also a good starting point for debugging the Spring Security processing.

In our sample project (using Spring Boot 2.3.1 and Spring Security 5.3.3) the SecurityFilterChain contains the following filters (identified by debugging into FilterChainProxy.doFilter(...) and looking into this.filterChains[0].filters).

org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
org.springframework.security.web.context.SecurityContextPersistenceFilter
org.springframework.security.web.header.HeaderWriterFilter
org.springframework.security.web.authentication.logout.LogoutFilter
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
org.springframework.security.web.authentication.AnonymousAuthenticationFilter
org.springframework.security.web.session.SessionManagementFilter
org.springframework.security.web.access.ExceptionTranslationFilter
org.springframework.security.web.access.intercept.FilterSecurityInterceptor
Let’s have a closer look at those filters that are relevant for our purpose and how to extend and customize their behaviour.

## SecurityContextPersistenceFilter
From the API documentation: “Populates the SecurityContextHolder with information obtained from the configured SecurityContextRepository prior to the request and stores it back in the repository once the request has completed and clearing the context holder.”

The SecurityContext mainly represents the persisted session. It contains an Authentication which in the context of a web application encapsulates the information of the authenticated user. The default implementation of the SecurityContextRepository stores the SecurityContext in the HttpSession. To change this behaviour we have to provide our own SecurityContextRepository implementation.

    @Component
      public class CookieSecurityContextRepository implements SecurityContextRepository {

      private static final String EMPTY_CREDENTIALS = "";
      private static final String ANONYMOUS_USER = "anonymousUser";

      private final String cookieHmacKey;

      public CookieSecurityContextRepository(@Value("${auth.cookie.hmac-key}") String cookieHmacKey) {
        this.cookieHmacKey = cookieHmacKey;
      }

      @Override
      public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        requestResponseHolder.setResponse(new SaveToCookieResponseWrapper(request, response));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        readUserInfoFromCookie(request).ifPresent(userInfo ->
          context.setAuthentication(new UsernamePasswordAuthenticationToken(userInfo, EMPTY_CREDENTIALS, userInfo.getAuthorities())));

        return context;
      }

      @Override
      public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        SaveToCookieResponseWrapper responseWrapper = (SaveToCookieResponseWrapper) response;
        if (!responseWrapper.isContextSaved()) {
          responseWrapper.saveContext(context);
        }
      }

      @Override
      public boolean containsContext(HttpServletRequest request) {
        return readUserInfoFromCookie(request).isPresent();
      }

      private Optional<UserInfo> readUserInfoFromCookie(HttpServletRequest request) {
        return readCookieFromRequest(request)
          .map(this::createUserInfo);
      }

      private Optional<Cookie> readCookieFromRequest(HttpServletRequest request) {
        if (request.getCookies() == null) {
          return Optional.empty();
        }

        Optional<Cookie> maybeCookie = Stream.of(request.getCookies())
          .filter(c -> SignedUserInfoCookie.NAME.equals(c.getName()))
          .findFirst();

        return maybeCookie;
      }

      private UserInfo createUserInfo(Cookie cookie) {
        return new SignedUserInfoCookie(cookie, cookieHmacKey).getUserInfo();
      }

      private class SaveToCookieResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {
        private final HttpServletRequest request;

        SaveToCookieResponseWrapper(HttpServletRequest request, HttpServletResponse response) {
          super(response, true);
          this.request = request;
        }

        @Override
        protected void saveContext(SecurityContext securityContext) {
          HttpServletResponse response = (HttpServletResponse) getResponse();
          Authentication authentication = securityContext.getAuthentication();

          // some checks, see full sample code

          UserInfo userInfo = (UserInfo) authentication.getPrincipal();
          SignedUserInfoCookie cookie = new SignedUserInfoCookie(userInfo, cookieHmacKey);
          cookie.setSecure(request.isSecure());
          response.addCookie(cookie);
        }
      }
    }

The UserInfo in our sample project is a very simple POJO that implements the UserDetails interface and contains the information that we want to hold in our user session.

The SaveToCookieResponseWrapper gets the UserInfo from the SecurityContext and puts it into a SignedUserInfoCookie. The SignedUserInfoCookie is an extension of javax.servlet.http.Cookie that handles the serialization and deserialization of the UserInfo into/from the cookie value.

    public class SignedUserInfoCookie extends Cookie {

      public static final String NAME = "UserInfo";
      private static final String PATH = "/";
      private static final Pattern UID_PATTERN = Pattern.compile("uid=([A-Za-z0-9]*)");
      private static final Pattern ROLES_PATTERN = Pattern.compile("roles=([A-Z0-9_|]*)");
      private static final Pattern COLOUR_PATTERN = Pattern.compile("colour=([A-Z]*)");
      private static final Pattern HMAC_PATTERN = Pattern.compile("hmac=([A-Za-z0-9+/=]*)");
      private static final String HMAC_SHA_512 = "HmacSHA512";

      private final Payload payload;
      private final String hmac;

      public SignedUserInfoCookie(UserInfo userInfo, String cookieHmacKey) {
        super(NAME, "");
        this.payload = new Payload(
          userInfo.getUsername(),
          userInfo.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList()),
          userInfo.getColour().orElse(null));
        this.hmac = calculateHmac(this.payload, cookieHmacKey);
        this.setPath(PATH);
        this.setMaxAge((int) Duration.of(1, ChronoUnit.HOURS).toSeconds());
        this.setHttpOnly(true);
      }

      public SignedUserInfoCookie(Cookie cookie, String cookieHmacKey) {
        super(NAME, "");

        if (!NAME.equals(cookie.getName()))
          throw new IllegalArgumentException("No " + NAME + " Cookie");

        this.hmac = parse(cookie.getValue(), HMAC_PATTERN).orElse(null);
        if (hmac == null)
          throw new CookieVerificationFailedException("Cookie not signed (no HMAC)");

        String username = parse(cookie.getValue(), UID_PATTERN).orElseThrow(() -> new IllegalArgumentException(NAME + " Cookie contains no UID"));
        List<String> roles = parse(cookie.getValue(), ROLES_PATTERN).map(s -> List.of(s.split("\\|"))).orElse(List.of());
        String colour = parse(cookie.getValue(), COLOUR_PATTERN).orElse(null);
        this.payload = new Payload(username, roles, colour);

        if (!hmac.equals(calculateHmac(payload, cookieHmacKey)))
          throw new CookieVerificationFailedException("Cookie signature (HMAC) invalid");

        this.setPath(cookie.getPath());
        this.setMaxAge(cookie.getMaxAge());
        this.setHttpOnly(cookie.isHttpOnly());
      }

      private static Optional<String> parse(String value, Pattern pattern) {
        Matcher matcher = pattern.matcher(value);
        if (!matcher.find())
          return Optional.empty();

        if (matcher.groupCount() < 1)
          return Optional.empty();

        String match = matcher.group(1);
        if (match == null || match.trim().isEmpty())
          return Optional.empty();

        return Optional.of(match);
      }

      @Override
      public String getValue() {
        return payload.toString() + "&hmac=" + hmac;
      }

      public UserInfo getUserInfo() {
        return new UserInfo(
          payload.username,
          payload.roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()),
          payload.colour);
      }

      private String calculateHmac(Payload payload, String secretKey) {
        byte[] secretKeyBytes = Objects.requireNonNull(secretKey).getBytes(StandardCharsets.UTF_8);
        byte[] valueBytes = Objects.requireNonNull(payload).toString().getBytes(StandardCharsets.UTF_8);

        try {
          Mac mac = Mac.getInstance(HMAC_SHA_512);
          SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, HMAC_SHA_512);
          mac.init(secretKeySpec);
          byte[] hmacBytes = mac.doFinal(valueBytes);
          return Base64.getEncoder().encodeToString(hmacBytes);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
      }

      private static class Payload {
        private final String username;
        private final List<String> roles;
        private final String colour;

        private Payload(String username, List<String> roles, String colour) {
          this.username = username;
          this.roles = roles;
          this.colour = colour;
        }

        @Override
        public String toString() {
          return "uid=" + username +
            "&roles=" + String.join("|", roles) +
            (colour != null ? "&colour=" + colour : "");
        }
      }
    }

The cookie value has to follow RFC-6265 which allows only a few non-alphabetical characters (see Stack Overflow answer for a good summary), for example no whitespace, quotes or brackets are allowed. So we can’t use a JSON structure to serialize our payload, which would probably be easier to handle, especially to parse. We could have encoded the payload with Base64 before writing it into the cookie. However, the idea of the sample project was to keep the cookie value unencoded and human-readable, so we decided for the individual format.

As the cookie contains the id and the roles of the authenticated user, we have to make sure that the value is not modified on the client side. To do this our sample application signs the cookie by computing a HMAC (hash-based message authentication code) of the payload and appending it to the cookie value. That’s a quite simple approach and there are probably better and more secure ways of securing the cookie. One option might be JWT which provides a standardized way to securely exchange sensitive data. But, this is a topic of its own and out of the scope of this blog post.

(Thanks to Christian Köberl, @derkoe, for his feedback and ideas to improve the security of the cookie)

When the SecurityContext is requested via SecurityContextRepository.loadContext(...), the javax.servlet.http.Cookie from the HttpServletRequest is transformed into a SignedUserInfoCookie again. The cookie value is verified using the HMAC signature. A CookieVerificationFailedException will be thrown if the received cookie is unsigned or the HMAC does not fit to the value. Finally, the UserInfo is retrieved from the SignedUserInfoCookie, wrapped in a UsernamePasswordAuthenticationToken and set into the SecurityContext.

UsernamePasswordAuthenticationFilter
From the API documentation: “Processes an authentication form submission.”

See also Chapter 10 of the Spring Security Reference for a detailed description of the Spring Security authentication process.

The UsernamePasswordAuthenticationFilter triggers the authentication, if necessary and possible. It reads username and password from a login form request, wraps them into a UsernamePasswordAuthenticationToken and calls the configured AuthenticationManager to perform the authentication.

In the default configuration, the AuthenticationManager is a ProviderManager which holds a list of AuthenticationProviders to which it delegates the authentication request. In our sample project we use a very basic InMemoryAuthenticationProvider which knows only one static user. In a real world project we would instead use a database or LDAP provider (from the Spring Security LDAP module).

After a successful login the configured AuthenticationSuccessHandler is called. Usually, this handler decides about where to forward the user to after the successful login. In the default configuration a SavedRequestAwareAuthenticationSuccessHandler is used. It loads and replays the original request (which was cached before by the ExceptionTranslationFilter, see next section) to show the page to the user which he/she originally requested. As this RequestCache is also stored in the server-side session, we have to find another strategy for this feature as well.



https://www.innoq.com/en/blog/cookie-based-spring-security-session/
https://github.com/innoq/cookie-based-session-springboot-app

package demo;

import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@ComponentScan
@EnableAutoConfiguration
@RestController
@RequestMapping("/dashboard")
@EnableOAuth2Client
public class SsoApplication {

	@Bean
	public Filter filter() {
		DelegatingFilterProxy f = new DelegatingFilterProxy();
		f.setTargetBeanName("oauth2ClientContextFilter");
		return f;
	}

	@Autowired
	public OAuth2ClientContext oauth2ClientContext;

	@Bean
	public OAuth2RestTemplate restTemplate() {
		return new OAuth2RestTemplate(remote(), oauth2ClientContext);
	}

	@Bean
	public OAuth2ProtectedResourceDetails remote() {
		return new AuthorizationCodeResourceDetails();
	}

	@RequestMapping("/message")
	public Map<String, Object> dashboard(HttpServletRequest request, Principal user) {
		HttpSession session = request.getSession();
		Enumeration<String> attributeNames = session.getAttributeNames();
		String sessionAttributeNames = "";
		while(attributeNames.hasMoreElements()) {
			sessionAttributeNames += ", " + attributeNames.nextElement();
		}
		return Collections.<String, Object> singletonMap("message", "Yay! session: " + sessionAttributeNames);
	}

	@RequestMapping("/user")
	public Principal user(Principal user) {
		OAuth2RestTemplate restTemplate = restTemplate();
		System.out.println(restTemplate.getAccessToken());
		Map mapFromAuthServer = restTemplate.getForObject("http://localhost:8080/uaa/message", Map.class);
		System.out.println("mapFromAuthServer: " + mapFromAuthServer);
		return user;
	}

	@RequestMapping("/enter")
	public void enter(Principal user, HttpServletResponse response) {
		try {
			response.sendRedirect("/#/");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	public static void main(String[] args) {
		SpringApplication.run(SsoApplication.class, args);
	}

	@Controller
	public static class LoginErrors {

		@RequestMapping("/dashboard/login")
		public String dashboard() {
			return "redirect:/#/";
		}

	}

	@Component
	@EnableOAuth2Sso
	public static class LoginConfigurer extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/dashboard/**").authorizeRequests().anyRequest()
					.authenticated().and().csrf().disable()
					/*
					.csrfTokenRepository(csrfTokenRepository()).and()
					.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
					*/
					.logout().logoutUrl("/dashboard/logout").permitAll()
					.logoutSuccessUrl("/");
			//.and().antMatcher("/dashboard/enter").authorizeRequests().anyRequest().permitAll();
		}

		private Filter csrfHeaderFilter() {
			return new OncePerRequestFilter() {
				@Override
				protected void doFilterInternal(HttpServletRequest request,
						HttpServletResponse response, FilterChain filterChain)
						throws ServletException, IOException {
					CsrfToken csrf = (CsrfToken) request
							.getAttribute(CsrfToken.class.getName());
					if (csrf != null) {
						Cookie cookie = new Cookie("XSRF-TOKEN",
								csrf.getToken());
						cookie.setPath("/");
						response.addCookie(cookie);
					}
					filterChain.doFilter(request, response);
				}
			};
		}

		private CsrfTokenRepository csrfTokenRepository() {
			HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
			repository.setHeaderName("X-XSRF-TOKEN");
			return repository;
		}
	}
}

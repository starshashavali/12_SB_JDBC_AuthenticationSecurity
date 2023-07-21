package com.tcs.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private BCryptPasswordEncoder encoder;

	/**
	 * In this method we will configure Authentication credentials
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.usersByUsernameQuery("select user_name,user_pwd,user_enabled from user_dtls where user_name=?")
			.authoritiesByUsernameQuery("select user_name,user_role from user_dtls where user_name=?")
			.passwordEncoder(encoder);
	}

	/**
	 * This method we will configure Authorization roles
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
			http.authorizeRequests()
				.antMatchers("/home").permitAll()
				.antMatchers("/welcome").authenticated()
				.antMatchers("/admin").hasAuthority("ADMIN")
				.antMatchers("/emp").hasAuthority("EMPLOYEE")
				.antMatchers("/mgr").hasAuthority("MANAGER")
				.antMatchers("/common").hasAnyAuthority("EMPLOYEE", "MANAGER")
				
				.anyRequest().authenticated()
				
				.and()
				.formLogin()
				.defaultSuccessUrl("/welcome",true)
				
				.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				
				.and()
				.exceptionHandling()
				.accessDeniedPage("/accessDenied");
	}

}

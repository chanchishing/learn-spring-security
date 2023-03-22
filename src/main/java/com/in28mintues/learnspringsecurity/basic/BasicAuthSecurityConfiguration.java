package com.in28mintues.learnspringsecurity.basic;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->{
           auth.anyRequest().authenticated();
        });
        http.sessionManagement(session->{
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });

        http.httpBasic();

        http.formLogin().disable();

        http.csrf().disable();

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsSErvice() {

        var user=User.withUsername("in28minutes")
                        .password("{noop}dummy")
                        .roles("USER")
                        .build();
        //aW4yOG1pbnV0ZXM6ZHVtbXk=

        var admin=User.withUsername("admin")
                .password("{noop}dummy")
                .roles("ADMIN")
                .build();
        //YWRtaW46ZHVtbXk=

        return new InMemoryUserDetailsManager(user,admin);
    }
}

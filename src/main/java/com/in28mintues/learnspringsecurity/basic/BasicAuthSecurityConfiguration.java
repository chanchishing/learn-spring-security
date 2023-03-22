package com.in28mintues.learnspringsecurity.basic;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

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

        //for h2 console using HTML frames
        http.headers().frameOptions().sameOrigin();

        return http.build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        var user=User.withUsername("in28minutes")
//                        .password("{noop}dummy")
//                        .roles("USER")
//                        .build();
//        //aW4yOG1pbnV0ZXM6ZHVtbXk=
//
//        var admin=User.withUsername("admin")
//                .password("{noop}dummy")
//                .roles("ADMIN")
//                .build();
//        //YWRtaW46ZHVtbXk=
//
//        return new InMemoryUserDetailsManager(user,admin);
//    }

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                //using the User schema provided by Spring Security
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {

        var user=User.withUsername("in28minutes")
                        .password("{noop}dummy")
                        .roles("USER")
                        .build();
        //aW4yOG1pbnV0ZXM6ZHVtbXk=

        var admin=User.withUsername("admin")
                .password("{noop}dummy")
                .roles("ADMIN","USER")
                .build();
        //YWRtaW46ZHVtbXk=

        var jdbcUserDetailsManager= new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }
}

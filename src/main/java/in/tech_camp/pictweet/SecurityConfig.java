package in.tech_camp.pictweet;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import in.tech_camp.pictweet.custom_user.CustomUserDetail;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                //リクエスト許可設定
                .cors(cors -> cors
                .configurationSource(request -> {
                    var corsConfiguration = new org.springframework.web.cors.CorsConfiguration();
                    //許可URL
                    corsConfiguration.setAllowedOrigins(List.of("http://localhost:3000"));
                    //許可リクエストタイプ
                    corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedHeaders(List.of("*"));
                    return corsConfiguration;
                    })
                )
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                    .requestMatchers(HttpMethod.GET, "/css/**", "/images/**", "/error").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/tweets/", "/api/tweets/{id:[0-9]+}", "/api/users/{id:[0-9]+}", "/api/tweets/search").permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/users/", "/api/login").permitAll()
                    .anyRequest().authenticated())
                        //上記以外のリクエストは認証されたユーザーのみ許可されます(要ログイン)
                
                .formLogin(login -> login
                    //ログインフォームでログインボタンを押した際のパスを設定しています
                    .loginProcessingUrl("/api/login")
                    //ログイン時にusernameとして扱うパラメーターを指定します
                    .usernameParameter("email")
                    .successHandler(authenticationSuccessHandler())
                    .failureHandler((request, response, exception) -> {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write(
                            "{\"error\":\"Invalid credentials\"}"
                        );
                    })
                )

                .logout(logout -> logout
                        //ログアウトボタンを押した際のパスを設定しています
                        .logoutUrl("/api/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                        response.setStatus(HttpServletResponse.SC_OK);
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write("{\"success\":true}");
                    })
                );
                        
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            CustomUserDetail userDetails = (CustomUserDetail) authentication.getPrincipal();

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(String.format(
                "{\"id\":%d,\"nickname\":\"%s\",\"email\":\"%s\"}",
                userDetails.getId(),
                userDetails.getNickname(),
                userDetails.getUsername()
            ));
        };
    }

}

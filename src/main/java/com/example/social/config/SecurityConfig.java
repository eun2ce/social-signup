package com.example.social.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // Spring Security 의 웹 보안 지원을 활성화하고, 보안 설정을 제공
@RequiredArgsConstructor  // Lombok 어노테이션으로, 클래스 필드를 모두 인자로 받는 생성자를 자동으로 생성
public class SecurityConfig {

  private final Environment environment;  // Spring 환경 설정을 통해 애플리케이션 프로퍼티에 접근합니다.
  private final String registration = "spring.security.oauth2.client.registration.";  // OAuth2 클라이언트 등록 프로퍼티의 접두어입니다.
  private final GoogleOAuth2UserService googleOAuth2UserService;  // Google OAuth2 사용자 정보를 처리하는 서비스.

  @Bean
  protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // HTTP 보안 설정
    http
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/login", "/index").permitAll()  // /login, /index 경로는 인증 없이 접근 가능
            .anyRequest().authenticated()  // 그 외의 요청은 인증이 필요
        )
        .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(
                    clientRegistrationRepository())  // OAuth2 클라이언트 등록을 위한 레포지토리 설정
                .authorizedClientService(authorizedClientService())  // 인증된 클라이언트 정보를 처리하는 서비스 설정
                .userInfoEndpoint(user -> user
                        .oidcUserService(
                            googleOAuth2UserService)  // Google 인증에 사용할 사용자 서비스 (OpenID Connect)
//                .userService(facebookOauth2UserService)  // Facebook 인증에 사용할 사용자 서비스 (OAuth2)
                )
        );
    return http.build();
  }

  @Bean
  public OAuth2AuthorizedClientService authorizedClientService() {
    // OAuth2 인증된 클라이언트 정보를 관리하는 서비스 (여기서는 InMemory 사용)
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
  }

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    // OAuth2 클라이언트 등록 정보를 관리하는 레포지토리
//    final List<ClientRegistration> clientRegistrations = Arrays.asList(
//        googleClientRegistration(),  // Google OAuth2 클라이언트 등록
//        facebookClientRegistration()  // Facebook OAuth2 클라이언트 등록
//    );

    return new InMemoryClientRegistrationRepository(
        googleClientRegistration());  // 메모리 기반 클라이언트 등록 레포지토리
  }

  private ClientRegistration googleClientRegistration() {
    // Google OAuth2 클라이언트 등록을 설정
    final String clientId = environment.getProperty(
        registration + "google.client-id");  // 애플리케이션 프로퍼티에서 Google client-id 가져오기
    final String clientSecret = environment.getProperty(
        registration + "google.client-secret");  // 애플리케이션 프로퍼티에서 Google client-secret 가져오기

    // Google OAuth2 클라이언트 등록을 반환
    return CommonOAuth2Provider
        .GOOGLE
        .getBuilder("google")  // Google 클라이언트 등록 식별자
        .clientId(clientId)  // client-id 설정
        .clientSecret(clientSecret)  // client-secret 설정
        .build();
  }

//  private ClientRegistration facebookClientRegistration() {
//    // Facebook OAuth2 클라이언트 등록을 설정
//    final String clientId = environment.getProperty(
//        registration + "facebook.client-id");  // 애플리케이션 프로퍼티에서 Facebook client-id 가져오기
//    final String clientSecret = environment.getProperty(
//        registration + "facebook.client-secret");  // 애플리케이션 프로퍼티에서 Facebook client-secret 가져오기
//
//    // Facebook OAuth2 클라이언트 등록을 반환
//    return CommonOAuth2Provider
//        .FACEBOOK
//        .getBuilder("facebook")  // Facebook 클라이언트 등록 식별자
//        .clientId(clientId)  // client-id 설정
//        .clientSecret(clientSecret)  // client-secret 설정
//        .scope(  // Facebook에서 요청할 권한(스코프) 설정
//            "public_profile",  // 사용자 공개 프로필에 접근
//            "email",  // 사용자 이메일에 접근
//            "user_birthday",  // 사용자 생일에 접근
//            "user_gender"  // 사용자 성별에 접근
//        )
//        .userInfoUri(
//            "https://graph.facebook.com/me?fields=id,name,email,picture,gender,birthday")  // Facebook에서 사용자 정보를 가져올 URI
//        .build();
//  }
}

package com.example.social.config;

import com.example.social.user.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor // Lombok 어노테이션으로 final 필드들을 인자로 받는 생성자를 자동 생성
public class GoogleOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

  private final UserRegistrationService userRegistrationService; // 사용자 등록 서비스, 인증된 사용자의 정보 처리

  @Override
  public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthorizationException {
    // OidcUserService 를 사용하여 OIDC 사용자 정보를 로드
    final OidcUserService oidcUserService = new OidcUserService();
    final OidcUser oidcUser = oidcUserService.loadUser(userRequest); // 사용자 정보 로드

    // 액세스 토큰을 가져옵니다. 이 토큰을 사용해 추가적인 API 요청을 할 수 있습니다.
    final OAuth2AccessToken accessToken = userRequest.getAccessToken();

    // 액세스 토큰을 사용하여 외부 API 호출 (예: Google People API)
    // String profileInfo = fetchUserProfileInfo(accessToken);

    // Google 에서 제공하는 사용자 정보 중 'name' 과 'email' 을 추출하여 변수에 저장
    final String name = oidcUser.getAttributes().get("name").toString();
    final String email = oidcUser.getAttributes().get("email").toString();

    // 사용자 정보를 사용자 등록 서비스에 전달하여 등록 절차를 요청
    userRegistrationService.requestRegistration(name, email);

    // 인증된 사용자 정보를 반환
    return new DefaultOidcUser(
        oidcUser.getAuthorities(), // 사용자의 권한 정보
        oidcUser.getIdToken(), // OIDC 토큰
        oidcUser.getUserInfo() // 사용자 정보
    );
  }

//  private String fetchUserProfileInfo(OAuth2AccessToken accessToken) {
//    // 액세스 토큰을 Authorization 헤더에 추가하여 Google People API 호출
//    String apiUrl = "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses";
//    RestTemplate restTemplate = new RestTemplate();
//
//    // Google People API에 요청을 보내기 위한 HTTP 헤더 설정
//    String authHeader = "Bearer " + accessToken.getTokenValue();
//    String response = restTemplate.getForObject(apiUrl, String.class, authHeader);
//
//    // 여기서 response를 적절히 처리하여 사용자 프로필을 반환하거나 저장합니다.
//    return response;  // Google API로부터 받은 응답을 반환
//  }
}

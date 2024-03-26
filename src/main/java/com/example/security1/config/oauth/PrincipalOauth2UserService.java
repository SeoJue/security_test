package com.example.security1.config.oauth;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.GoogleUserInfo;
import com.example.security1.config.oauth.provider.KakaoUserInfo;
import com.example.security1.config.oauth.provider.NaverUserInfo;
import com.example.security1.config.oauth.provider.Oauth2UserInfo;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;


//oauth 로그인 후 처리 로직 컴포넌트
// 1.코드받기(인증), 2.엑세스 토큰(권한), 3.사용자 프로필 정보를 가져옴
// 4-1.그 정보를 토대로 회원가입, 4-2.client 서비스가 필요한 추가정보를 요구 후 회원가입 <- 이 부분을 담당
@Service
public class PrincipalOauth2UserService extends  DefaultOAuth2UserService{

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    //resource service로 부터 받은 userRequest 데이터에 대한 후처리 함수
    //userRequest는 resource owner 인증 후 resource server로 부터 받게되는 데이터를 가짐(accessToken과 유저 정보등)
    //함수 종료시 @AuthenticationPrincipal annotation이 만들어짐
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //clientRegistration: client 정보, 어떤 oauth로 로그인 했는지 알 수 있음 (provider가 제공)
        System.out.println("clientRegistration: " + userRequest.getClientRegistration());

        //구글 로그인 버튼 -> 구글 로그인창 -> 로그인 완료 -> authorization code를 리턴(OAuth-Client 라이브러리가 받음)
        // -> code 기반 accessToken 요청 -> AccessToken은 userRequest에 담김
        System.out.println("accessToken: " + userRequest.getAccessToken().getTokenValue());

        //userRequest 정보 -> loadUser 함수 호출 -> google로 부터 회원 프로필을 받아줌
        //System.out.println("loadUser().getAttributes: " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("loadUser().getAttributes: " + oAuth2User.getAttributes());

        //유저 정보를 기반으로 회원가입
        /*
        String provider = userRequest.getClientRegistration().getRegistrationId(); //google
        String providerId = oAuth2User.getAttribute("sub"); // google의 resource owner, client에 대한 pk
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("getInThere");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";
        */

        Oauth2UserInfo oauth2UserInfo = null;

        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("google login");
            oauth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("naver login");
            oauth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("kakao")){
            System.out.println("kakao login");
            oauth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
        }
        else{
            System.out.println("we support google, naver and kakao");
        }

        String provider = oauth2UserInfo.getProvider();
        String providerId = oauth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("getInThere");
        String email = oauth2UserInfo.getEmail();
        String role = "ROLE_USER";


        User userEntity = userRepository.findByUsername(username);

        if(userEntity==null){
            userEntity = User.builder().username(username).password(password).email(email)
                    .role(role).provider(provider).providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}

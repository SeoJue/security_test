package com.example.security1.config.auth;

//시큐리티가 /login (loginProcessingUrl로 등록됨)주소 요청을 낚아채서 로그인을 진행시킴
//로그인 진행이 완료가 되면 시큐리티 session을 만들어줌 (Security ContextHolder)
//세션에 들어가는 오브젝트 -> Authentication 타입 객체
//Authentication <- User 정보를 가짐
//User의 오브젝트 타입 -> UserDetails 타입 객체

//요약 Security Session (세션 영역) -> Authentication -> UserDetails(PrincipalDetails)


import com.example.security1.model.User;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

// /login 요청을 낚아채 정상 수행될 경우 해당 객체를 시큐리티 세션에 저장함 (Authentication 객체에 담겨)

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;

    //컴포지션
    private Map<String, Object> attributes;

    //일반 로그인 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //oauth 로그인 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    //해당 User의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {

        //만료 계정 여부 판단
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {

        //잠긴 계정 여부 판단
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        //비밀번호 만료 기한 여부 파단
        return true;
    }

    @Override
    public boolean isEnabled() {

        //휴면 계정 여부 (판단은 로직 구현)
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        //sub: resource owner에 대한 resource server의 primary key
        return (String) attributes.get("sub");
    }
}

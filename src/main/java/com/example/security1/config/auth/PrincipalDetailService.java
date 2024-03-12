package com.example.security1.config.auth;

import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessingUrl로 걸어놓은 요청(/login)이 오면
// 자동으로 IoC되어있는 UserDetailsService 내부 loadUserByUsername 함수가 실행됨


//loginForm Action -> /login 요청 -> login 검증 -> UserDetailService 호출 -> loadUserByUsername() 수행
@Service
public class PrincipalDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    //함수 종료시 @AuthenticationPrincipal annotation이 만들어짐
    @Override   //form에서 넘겨주는 데이터 이름은 반드시 "username" 이어야 함
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);

        System.out.println("PrincipalDetailService.loadUserByUsername");

        // 리턴된 값은 Authentication 내부에 들어감 -> Authentication 은 시큐리티 session 으로 들어감
        if(userEntity!=null){
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}

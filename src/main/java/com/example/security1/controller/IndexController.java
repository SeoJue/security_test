package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class IndexController {

    private UserRepository userRepository;
    private BCryptPasswordEncoder pwdEncoder;

    @Autowired
    public IndexController(UserRepository userRepository, BCryptPasswordEncoder pwdEncoder) {
        this.userRepository = userRepository;
        this.pwdEncoder = pwdEncoder;
    }

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, //security session에 잇는 Authentication이 자동 주입됨
                            @AuthenticationPrincipal PrincipalDetails userDetails){ //annotation으로 더 쉽게 UserDetails를 가져올 수 있음
        System.out.println("/test/login ===================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        //Authentication을 주입 받아 내부 UserDetails를 가져옴으로서 User 참조 가능
        System.out.println("authentication: " +  principalDetails.getUser());
        System.out.println("userDetails: " + userDetails.getUser());

        return "verifying session";
    }

    //oauth 버전
    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOauthLogin(Authentication authentication,
                                 @AuthenticationPrincipal OAuth2User oauth){
        System.out.println("/test/login ===================");
        
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        System.out.println("authentication: " +  oAuth2User.getAttributes());
        System.out.println("oauth2User: " + oauth.getAttributes());

        return "verifying oauth session";
    }


    @GetMapping({"","/"})
    public String index(){
        //머스테치 기본 폴더 src/main/resources/
        //뷰 리졸버 설정: templates(prefix), .mustache(suffix) <- 기본 설정이기에 생략 가능
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){

        System.out.println("principalDetails: " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(@ModelAttribute User user){
        user.setRole("ROLE_USER");

        //패스워드 암호화를 하지않으면 회원가입은 잘되나 시큐리티로 로그인 불가능(패스워드 암호화 필수)
        String rawPassword = user.getPassword();
        String encPassword = pwdEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    //하나의 특정 메서드에 인증절차를 줄 때 사용 (hasRole('')를 사용하면 여러 ROLE에 권한을 줄 수 있음)
    @Secured("USER")
    @GetMapping("/info")
    @ResponseBody
    public String info(){
        return "private info";
    }

    //메서드 실행 전 인증 활성화(Secured와 동일한 기능)
    @PreAuthorize("hasRole('MANAGER') or hasRole('ADMIN')")
    //메서드 실행 후 인증 활성화(자주 사용하지는 않음)
    //@PostAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data(){
        return "private data";
    }
}

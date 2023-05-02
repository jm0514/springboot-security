package com.study.security.config.auth;

//시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행한다.
//로그인을 진행 완료하면 시큐리티 session을 만들어 준다.(Security ContextHolder)
//오브젝트 타입 -> Authentication 타입 객체
//Authentication 안에 User정보가 있어야됨.
//User오브젝트타입 -> UserDetails 타입 객체

//Security Session -> Authentication -> UserDetails -> UserDetails(PrincipalDetails)

import com.study.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user; //컴포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    //해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
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
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //현재 사이트 1년동안 회원이 로그인 안하면 휴면 계정으로 하기로 함.
        //현재시간 - 로긴시간 -> 1년 초과하면 return false;
       return true;
    }
}

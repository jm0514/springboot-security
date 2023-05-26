package com.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.auth.PrincipalDetails;
import com.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// login 요청에서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");

        // 1. username, password 받아
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
            //DB에 있는 username과 password가 일치한다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session영역에 저장됨 -> 로그인이 되었다.
            //단지 권한 처리 때문에 session에 넣어 준다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("=====================");
        // 2. 정상인지 로그인 시도 해봄 authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출
        // 3. 그 다음 loadUserByUsername() 함수 실행됨.
        // 4. PrincipalDetails를 세션에 담고(권한 관리를 위해)
        // 5. JWT토큰을 만들어서 응답해주면 됨

        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer" + jwtToken);

    }
}

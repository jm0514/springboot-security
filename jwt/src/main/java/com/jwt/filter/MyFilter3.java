package com.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰:cos 이것을 만들어야 한다. id, pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그것을 응답해준다.
        // 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 온다.
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증(RSA, HS256)
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터1");

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }
    }
}

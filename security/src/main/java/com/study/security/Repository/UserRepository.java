package com.study.security.Repository;

import com.study.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// @Repository 없이도 IoC됨. JpaRepository를 상속했기 때문임
public interface UserRepository extends JpaRepository<User, Integer> {
    //select * from user where username = 1?
    User findByUsername(String username);
}

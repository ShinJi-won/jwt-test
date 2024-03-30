package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.domain.Member;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    // 쿼리 메서드
    Member findMemberByEmail(String email);
}


package com.jsp.jpa.repository.review;

import com.jsp.jpa.model.review.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface ReviewRepository extends JpaRepository<Review, Long> {
    List<Review> findByMemberIdx(int memberIdx);
}
package com.jsp.jpa.controller.review;

import com.jsp.jpa.dto.review.ReviewDto;
import com.jsp.jpa.model.review.Review;
import com.jsp.jpa.repository.review.ReviewRepository;
import com.jsp.jpa.repository.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class ReviewController {

    @Autowired
    private ReviewRepository reviewRepository;
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/review")
    public Review createReview(@RequestBody Review review) {
        // 여기에서 필요에 따라 추가 로직을 수행할 수 있습니다.
        return reviewRepository.save(review);
    }
    @GetMapping("/reviews/{id}")
    public Review getReviewById(@PathVariable("id") Long id) {
        return reviewRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("리뷰를 찾을 수 없습니다. id: " + id));
    }

    @PostMapping("/my-reviews")
    public List<Review> getMyReviews(@RequestBody ReviewDto request) {
        return reviewRepository.findByMemberIdx(request.getMemberIdx());
    }

    @DeleteMapping("/reviews/{id}")
    public void deleteReview(@PathVariable("id") Long id) {
        Review review = reviewRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("리뷰를 찾을 수 없습니다. id: " + id));
        reviewRepository.delete(review);
    }
}
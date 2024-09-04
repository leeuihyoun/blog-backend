package com.jsp.jpa.model.review;

import jakarta.persistence.*;
import lombok.Data;


import java.time.LocalDateTime;

@Entity(name = "review")
@Data
public class Review {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "review_idx")
    private int reviewIdx;

    @Column(name = "member_idx")
    private int memberIdx;

    @Column(name = "review_title")
    private String reviewTitle;

    @Column(name = "review_content")
    private String reviewContent;

    @Column(name = "review_img")
    private String reviewImg;

    @Column(name = "review_date")
    private LocalDateTime reviewDate = LocalDateTime.now();

    @Column(name = "review_category")
    private int reviewCategory;



}
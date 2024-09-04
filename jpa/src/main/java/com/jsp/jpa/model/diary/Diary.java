package com.jsp.jpa.model.diary;

import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;

@Entity(name ="diary")
@Data
public class Diary {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "diary_idx")
    private int diaryIdx;

    @Column(name = "member_idx")
    private int memberIdx;

    @Column(name = "diary_date")
    private Date diaryDate;

    @Column(name = "diary_emoji")
    private int diaryEmoji;

    @Column(name = "diary_title")
    private String diaryTitle;

    @Column(name = "diary_content")
    private String diaryContent;


}

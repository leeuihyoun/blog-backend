package com.jsp.jpa.repository.diary;

import com.jsp.jpa.model.diary.Diary;
import com.jsp.jpa.model.review.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DiaryRepository extends JpaRepository<Diary, Integer> {
    List<Diary> findByMemberIdx(int memberIdx);
}

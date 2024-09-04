package com.jsp.jpa.controller.diary;

import com.jsp.jpa.dto.diary.DiaryDto;
import com.jsp.jpa.model.diary.Diary;
import com.jsp.jpa.repository.diary.DiaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class DiaryController {
    @Autowired
    private DiaryRepository diaryRepository;

    @PostMapping("/diaryInsert")
    public Diary creatediary(@RequestBody Diary diary) {
        // 여기에서 필요에 따라 추가 로직을 수행할 수 있습니다.
        return diaryRepository.save(diary);
    }

    @PostMapping("/my-diary")
    public List<Diary> getMyDiary(@RequestBody DiaryDto request) {
        return diaryRepository.findByMemberIdx(request.getMemberIdx());
    }
}
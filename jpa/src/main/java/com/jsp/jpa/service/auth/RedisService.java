package com.jsp.jpa.service.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
// redis를 관리하기 위한 서비스
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    @Transactional
    //{key, value] 값을 저장한다.
    public void setValues(String key, String value){
        log.info("key : " + key);
        log.info("value : " + value);
        redisTemplate.opsForValue().set(key, value);
        log.info("redis에 저장됨");
    }


    @Transactional
    // 만료시간 설정 -> 자동 삭제
    //값을 유효시간(timeout)과 함께 저장할 수 있다. 단위는 토큰의 유효기간 단위와 동일하게 milliseconds로 지정했다.
    public void setValuesWithTimeout(String key, String value, long timeout){
        redisTemplate.opsForValue().set(key, value, timeout, TimeUnit.MILLISECONDS);
    }

    /**
     * key 값을 사용해 value 값을 가져온다.
     */
    public String getValues(String key){
        return redisTemplate.opsForValue().get(key);
    }

    @Transactional
    /**
     * dkey 값을 사용해 데이터를 삭제한다.
     */
    public void deleteValues(String key) {
        redisTemplate.delete(key);
    }
}

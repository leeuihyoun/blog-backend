-- Drop existing tables if they exist
DROP TABLE IF EXISTS `review`;
DROP TABLE IF EXISTS `diary`;
DROP TABLE IF EXISTS `member`;

-- Create the member table
CREATE TABLE `member` (
    `member_idx` INT AUTO_INCREMENT NOT NULL COMMENT '유저의 인덱스',
    `member_email` VARCHAR(100) NOT NULL,
    `member_pwd` VARCHAR(20) NOT NULL,
    `member_provider` VARCHAR(6) NOT NULL DEFAULT '일반' COMMENT '"일반", "카카오", "네이버"',
    `member_role` VARCHAR(6) NOT NULL DEFAULT 'USER' COMMENT 'USER or ADMIN',
    PRIMARY KEY (`member_idx`),
    UNIQUE KEY `UK_member_email` (`member_email`)
);

-- Create the diary table
CREATE TABLE `diary` (
    `diary_idx` INT AUTO_INCREMENT NOT NULL COMMENT '다이어리 게시글 인덱스 번호',
    `member_idx` INT NOT NULL COMMENT '유저의 인덱스',
    `diary_date` DATE NOT NULL,
    `diary_emoji` INT NOT NULL COMMENT '1이면 좋음...',
    `diary_title` VARCHAR(100) NOT NULL,
    `diary_content` TEXT NOT NULL,
    PRIMARY KEY (`diary_idx`),
    FOREIGN KEY (`member_idx`) REFERENCES `member` (`member_idx`) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Create the review table
CREATE TABLE `review` (
    `review_idx` INT AUTO_INCREMENT NOT NULL,
    `member_idx` INT NOT NULL COMMENT '유저의 인덱스',
    `review_title` VARCHAR(40) NOT NULL,
    `review_content` TEXT NOT NULL,
    `review_img` TEXT NULL COMMENT '이미지 들의 구분은 ,',
    `review_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '수정하면 이게 바꾸기',
    `review_category` INT NOT NULL COMMENT '0:... 1:...',
    PRIMARY KEY (`review_idx`),
    FOREIGN KEY (`member_idx`) REFERENCES `member` (`member_idx`) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Add indexing for foreign keys
CREATE INDEX `IDX_member_idx_on_diary` ON `diary` (`member_idx`);
CREATE INDEX `IDX_member_idx_on_review` ON `review` (`member_idx`);

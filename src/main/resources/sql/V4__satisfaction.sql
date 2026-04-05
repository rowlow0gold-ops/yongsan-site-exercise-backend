CREATE TABLE page_satisfaction (
    id          BIGSERIAL PRIMARY KEY,
    page_path   VARCHAR(500) NOT NULL,          -- e.g. /board/board1/posts/228
    rating      VARCHAR(20)  NOT NULL,          -- 매우 만족, 만족, 보통, 불만, 매우 불만
    feedback    VARCHAR(200),                   -- optional text feedback
    ip_address  VARCHAR(45),                    -- prevent spam
    user_id     BIGINT,                         -- nullable (guest or member)
    created_at  TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_satisfaction_page ON page_satisfaction(page_path);
CREATE INDEX idx_satisfaction_created ON page_satisfaction(created_at);

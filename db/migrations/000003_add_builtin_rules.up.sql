CREATE TABLE detection_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    technique_id VARCHAR(32) NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Built-in dictionaries are versioned and idempotent; demo assets are never seeded here.
INSERT INTO detection_rules (rule_id, name, description, severity, technique_id, enabled) VALUES
    ('ICS-MODBUS-001', 'Modbus 非授权写操作', '检测未经授权的线圈或寄存器写入', 'critical', 'T0855', TRUE),
    ('ICS-TIME-002', '非工作时段控制指令', '检测预定维护窗口外的工业控制指令', 'high', 'T0855', TRUE),
    ('ICS-AUTH-003', '工业设备认证爆破', '检测短时间内的连续认证失败', 'high', 'T0806', TRUE),
    ('ICS-DISCOVERY-004', 'OT 网段端口扫描', '检测单一源对工业资产的多端口探测', 'medium', 'T0846', TRUE),
    ('ICS-PROCESS-005', '工艺参数越界', '检测超出预期运行范围的工艺值', 'high', 'T0836', TRUE)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    description = VALUES(description),
    severity = VALUES(severity),
    technique_id = VALUES(technique_id),
    enabled = VALUES(enabled);

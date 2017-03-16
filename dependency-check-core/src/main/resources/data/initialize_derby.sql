#
# This file is part of dependency-check-core.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.

DROP TABLE software;
DROP TABLE cpeEntry;
DROP TABLE reference;
DROP TABLE vulnerability;
DROP TABLE properties;

CREATE TABLE vulnerability (
    id int NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1, INCREMENT BY 1) PRIMARY KEY, 
    cve VARCHAR(20) UNIQUE,
    description VARCHAR(8000),
    cwe VARCHAR(10),
    cvssScore DECIMAL(3,1),
    cvssAccessVector VARCHAR(20),
    cvssAccessComplexity VARCHAR(20),
    cvssAuthentication VARCHAR(20),
    cvssConfidentialityImpact VARCHAR(20),
    cvssIntegrityImpact VARCHAR(20), 
    cvssAvailabilityImpact VARCHAR(20)
);

CREATE TABLE reference (
    cveid INT, name VARCHAR(1000),
    url VARCHAR(1000),
    source VARCHAR(255),
    CONSTRAINT fkReference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
);

CREATE TABLE cpeEntry (
    id INT NOT NULL GENERATED ALWAYS AS IDENTITY (START WITH 1, INCREMENT BY 1) PRIMARY KEY,
    cpe VARCHAR(250),
    vendor VARCHAR(255),
    product VARCHAR(255)
);


CREATE TABLE software (
    cveid INT,
    cpeEntryId INT,
    previousVersion VARCHAR(50),
    CONSTRAINT fkSoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE,
    CONSTRAINT fkSoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id)
);


CREATE TABLE properties (
    id varchar(50) PRIMARY KEY,
    value varchar(500)
);
INSERT INTO properties(id, value) VALUES ('version', '2.9');

CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(cpe);
CREATE INDEX idxCpeEntry ON cpeEntry(vendor, product);


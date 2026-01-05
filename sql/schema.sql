CREATE DATABASE  IF NOT EXISTS `maildb` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `maildb`;
-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: maildb
-- ------------------------------------------------------
-- Server version	8.0.44-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accounts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain_id` int NOT NULL,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `full_name` varchar(255) DEFAULT NULL,
  `storage_quota` int DEFAULT '10240',
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_domain_user` (`domain_id`,`username`),
  KEY `idx_username` (`username`),
  CONSTRAINT `accounts_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts`
--

LOCK TABLES `accounts` WRITE;
/*!40000 ALTER TABLE `accounts` DISABLE KEYS */;
INSERT INTO `accounts` VALUES (1,1,'user@example.com','$2a$12$HZK4P8rE5QiJLvHSgnxH1u3BY2G6p5Ubm.vr.6yROXnVDJzDaT45q','Test User',NULL,1,'2026-01-01 08:56:24','2026-01-05 14:24:59');
/*!40000 ALTER TABLE `accounts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `domains`
--

DROP TABLE IF EXISTS `domains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `domains` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain_name` varchar(255) NOT NULL,
  `max_account` int DEFAULT '10',
  `is_active` tinyint DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain_name` (`domain_name`),
  KEY `idx_domain_name` (`domain_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `domains`
--

LOCK TABLES `domains` WRITE;
/*!40000 ALTER TABLE `domains` DISABLE KEYS */;
INSERT INTO `domains` VALUES (1,'example.com',10,0,'2026-01-01 08:56:24','2026-01-01 08:56:24');
/*!40000 ALTER TABLE `domains` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `mailboxes`
--

DROP TABLE IF EXISTS `mailboxes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mailboxes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `account_id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `flags` varchar(512) DEFAULT '',
  `quota` int DEFAULT '1000000',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `uidvalidity` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_account_mailbox` (`account_id`,`name`),
  KEY `idx_name` (`name`),
  KEY `idx_mailboxes_account` (`account_id`),
  CONSTRAINT `mailboxes_ibfk_1` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `mailboxes`
--

LOCK TABLES `mailboxes` WRITE;
/*!40000 ALTER TABLE `mailboxes` DISABLE KEYS */;
INSERT INTO `mailboxes` VALUES (1,1,'INBOX','\\Inbox \\HasNoChildren ',1000000,'2026-01-01 08:56:24','2026-01-05 17:52:59',NULL),(2,1,'Sent','\\HasNoChildren \\Sent',1000000,'2026-01-01 08:56:24','2026-01-05 17:54:08',NULL),(3,1,'Drafts','\\HasNoChildren \\Drafts',1000000,'2026-01-01 08:56:24','2026-01-05 17:54:08',NULL),(4,1,'Trash','\\HasNoChildren \\Trash',1000000,'2026-01-01 08:56:24','2026-01-05 17:54:08',NULL),(5,1,'Spam','\\HasNoChildren \\Junk',1000000,'2026-01-01 08:56:24','2026-01-05 17:54:08',NULL),(6,1,'Sampah','\\HasNoChildren',1000000,'2026-01-05 18:06:18','2026-01-05 18:06:18',1767636);
/*!40000 ALTER TABLE `mailboxes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `messages` (
  `id` int NOT NULL AUTO_INCREMENT,
  `mailbox_id` int NOT NULL,
  `object_id` int NOT NULL,
  `flags` varchar(255) DEFAULT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `subject` text,
  `header` json DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_mailbox_uid` (`mailbox_id`,`object_id`),
  KEY `idx_uid` (`object_id`),
  KEY `idx_messages_mailbox` (`mailbox_id`),
  CONSTRAINT `fk_messages_1` FOREIGN KEY (`object_id`) REFERENCES `object_keys` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`mailbox_id`) REFERENCES `mailboxes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `messages`
--

LOCK TABLES `messages` WRITE;
/*!40000 ALTER TABLE `messages` DISABLE KEYS */;
/*!40000 ALTER TABLE `messages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `object_keys`
--

DROP TABLE IF EXISTS `object_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `size` int NOT NULL,
  `key` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `object_keys`
--

LOCK TABLES `object_keys` WRITE;
/*!40000 ALTER TABLE `object_keys` DISABLE KEYS */;
/*!40000 ALTER TABLE `object_keys` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-01-06  2:09:56

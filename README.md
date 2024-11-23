Asset Tracking System with Esp32 and AWS Iot Cloud Infrastructure 🛠️ for dedicated asset monitoring by location tracking with Iot Hardware (Esp32, location Module) and Aws Iot Core Service.
 Transformations with S3 for storage, Lambda for automation, DynamoDB for robust storage of location data, and API Gateway for posting live location data to Mobile and Web Applications hosted on Aws Cloud within a fully automated pipeline.

This project demonstrates the full process that transforms raw, unstructured data from an ESP32-based hardware location tracker into valuable insights. By leveraging Amazon Web Services (AWS).

𝗧𝗲𝗰𝗵𝗻𝗼𝗹𝗼𝗴𝗶𝗲𝘀 𝗨𝘀𝗲𝗱 👩🏻‍💻

AWS IoT Core: Facilitates the collection of location data via MQTT and manages rules for data storage. 
AWS Lambda: Automates and orchestrates the transformation of incoming location data. 
AWS S3: Provides a scalable storage solution for live location data by rewriting and organizing objects. 
AWS DynamoDB: Enables dynamic storage of location data with automatic scaling to meet demand. 
Python Boto3: Streamlines data processing and transformations, leveraging AWS services effectively.
𝗦𝗤𝗟: For querying the Mqtt/topic data in Iot rule.

𝗣𝗿𝗼𝗷𝗲𝗰𝘁 𝗪𝗼𝗿𝗸𝗳𝗹𝗼𝘄 🛠️:

Realtime Data Collection 📦
Collected live location data from the ESP32 device integrated with a location module. The data was structured to include asset identification and GPS coordinates, which was then transmitted and stored in an AWS S3 raw bucket.
Realtime Data Processing 🔍
Implemented an Iot Rule so that raw location data stored in the S3 bucket, enabling further processing and analysis.
Realtime Data Transformation 🔧
Developed a Python-based data processing pipeline to clean and transform the location data into a structured format, suitable for mapping and display. The processed data was stored in an S3 processed bucket.

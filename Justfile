deploy:
   mvn -P release -DskipTests clean package
   mvn -P release -DskipTests deploy
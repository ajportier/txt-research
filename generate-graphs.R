library(ggplot2)
library(lubridate)
library(reshape2)
data <- read.csv(file.choose(),header=TRUE)
data$date <- as.Date(data$date)

data_long <- melt(data, id="date")

p1 <- ggplot(data=data_long, aes(x=date, y=value, colour=variable)) +
  geom_line()

p1 + labs(title="Record Change Over Time",
          x = "Date", y = "Count", colour = "Record Type")

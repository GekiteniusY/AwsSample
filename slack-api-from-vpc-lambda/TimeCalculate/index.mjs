export const handler = async (event) => {
  // TODO implement

  const now = new Date();
  console.log("now UTC Date: ", now);

  const jstOffsetMilliSec = 9 * 3600 * 1000;
  const jstDate = new Date(now.getTime() + jstOffsetMilliSec);
  console.log("jstDate: ", jstDate);

  const currentHour = jstDate.getHours();
  console.log("currentHour: ", currentHour);

  const month = jstDate.getUTCMonth() + 1; // +1 because getUTCMonth start from 0
  const day = jstDate.getUTCDate();
  console.log("Month: ", month);
  console.log("day: ", day);

  const response = {
    statusCode: 200,
    body: JSON.stringify("Hello from Lambda!"),
  };
  return response;
};

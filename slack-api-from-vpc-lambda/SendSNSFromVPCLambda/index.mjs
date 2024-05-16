import { SNSClient,PublishCommand } from "@aws-sdk/client-sns";

const awsRegion = 'ap-northeast-1';
const snsClient = new SNSClient({region: awsRegion});
const TopicArn = 'arn:aws:sns:ap-northeast-1:221730116965:SlackSNSTest'

export const handler = async (event) => {
    
    const testJson = [
        {
            "userId": 1,
            "timestamp": "2023-10-16T09:00:00",
            "sex": "male",
            "age": 30,
            "greetingMessage": "こんにちは、元気ですか？"
        },
        {
            "userId": 2,
            "timestamp": "2023-10-16T09:15:00",
            "sex": "female",
            "age": 25,
            "greetingMessage": "おはようございます！"
        },
        {
            "userId": 3,
            "timestamp": "2023-10-16T09:30:00",
            "sex": "male",
            "age": 45,
            "greetingMessage": "今日はいい天気ですね。"
        },
        {
            "userId": 4,
            "timestamp": "2023-10-16T09:45:00",
            "sex": "female",
            "age": 28,
            "greetingMessage": "こんにちは！楽しい一日を過ごしましょう。"
        },
        {
            "userId": 5,
            "timestamp": "2023-10-16T10:00:00",
            "sex": "male",
            "age": 35,
            "greetingMessage": "お疲れさまです。"
        }
    ];
    
    const message = {
        TopicArn: TopicArn,
        Message: JSON.stringify(testJson),
        Subject: "THIS IS TEST MESSAGE FROM SendSNSFromVPCLambda",
        // MessageStructure: "json",
      };

    try {
        const command = new PublishCommand(message);
        const response = await snsClient.send(command);
        console.log('送信成功')
    } catch (error) {
        console.log('送信失敗');
        console.log(error);
    }

    // return response;
  };
  
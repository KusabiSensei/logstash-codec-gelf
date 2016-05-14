require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/json"
require "logstash/codecs/gelf"
require "logstash/event"
require "logstash/json"
require "insist"

describe LogStash::Codecs::Gelf do
  subject do
    next LogStash::Codecs::Gelf.new
  end

  context "#decode" do
    it "should return an event from json data" do
      data = {"foo" => "bar", "baz" => {"bah" => ["a","b","c"]}}
      subject.decode(LogStash::Json.dump(data)) do |event|
        insist { event.is_a? LogStash::Event }
        insist { event["foo"] } == data["foo"]
        insist { event["baz"] } == data["baz"]
        insist { event["bah"] } == data["bah"]
      end
    end

    it "should be fast", :performance => true do
      json = '{"message":"Hello world!","@timestamp":"2013-12-21T07:01:25.616Z","@version":"1","host":"Macintosh.local","sequence":1572456}'
      iterations = 500000
      count = 0

      # Warmup
      10000.times { subject.decode(json) { } }

      start = Time.now
      iterations.times do
        subject.decode(json) do |event|
          count += 1
        end
      end
      duration = Time.now - start
      insist { count } == iterations
      puts "codecs/json rate: #{"%02.0f/sec" % (iterations / duration)}, elapsed: #{duration}s"
    end

    context "processing plain text" do
      it "falls back to plain text" do
        decoded = false
        subject.decode("something that isn't json") do |event|
          decoded = true
          insist { event.is_a?(LogStash::Event) }
          insist { event["message"] } == "something that isn't json"
          insist { event["tags"] }.include?("_jsonparsefailure")
        end
        insist { decoded } == true
      end
    end

    context "processing weird binary blobs" do
      it "falls back to plain text and doesn't crash (LOGSTASH-1595)" do
        decoded = false
        blob = (128..255).to_a.pack("C*").force_encoding("ASCII-8BIT")
        subject.decode(blob) do |event|
          decoded = true
          insist { event.is_a?(LogStash::Event) }
          insist { event["message"].encoding.to_s } == "UTF-8"
        end
        insist { decoded } == true
      end
    end

    context "when json could not be parsed" do

      let(:message)    { "random_message" }

      it "add the failure tag" do
        subject.decode(message) do |event|
          expect(event).to include "tags"
        end
      end

      it "uses an array to store the tags" do
        subject.decode(message) do |event|
          expect(event['tags']).to be_a Array
        end
      end

      it "add a json parser failure tag" do
        subject.decode(message) do |event|
          expect(event['tags']).to include "_jsonparsefailure"
        end
      end
    end
  end

  context "#encode" do
    it "should return a GELF 1.1 spec respecting json message" do
      # Let's put a syslog formatted message that will come to us, and then we will test for the correct output fields
      #data = {"message" => "dummyuser : command not allowed ; TTY=pts/1 ; PWD=/home/dummyuser/.rvm/gems/jruby-9.0.5.0/gems ; USER=root ; COMMAND=list", "host" => "0:0:0:0:0:0:0:1","facility_label" => "security/authorization" }
      data = {"message"=>"(root) CMD (run-parts /etc/cron.hourly)\n", "@version"=>"1", "@timestamp"=>"2016-05-13T23:01:01.000Z", "host"=>"s606306tr1vl10", "priority"=>78, "timestamp"=>"May 13 23:01:01", "logsource"=>"s606306tr1vl10", "program"=>"CROND", "pid"=>"26753", "severity"=>6, "facility"=>9, "facility_label"=>"clock", "severity_label"=>"Informational"}
      event = LogStash::Event.new(data)
      got_event = false
      subject.on_event do |e, d|
	# Current GELF Spec is v1.1
        insist { LogStash::Json.load(d)["version"] } == "1.1" 
       	insist { LogStash::Json.load(d)["host"] }.is_a? String
      	insist { LogStash::Json.load(d)["host"] } == data["host"]
      	# Make sure we get a numeric timestamp back
      	insist { LogStash::Json.load(d)["timestamp"] }.is_a? BigDecimal 
      	# Thou shalt not use _id under the GELF spec. It should never be set
      	insist { LogStash::Json.load(d)["_id"] }.nil? 
      	# Check a custom field to make sure we get the field name prepended with a _
      	insist { LogStash::Json.load(d)["_facility_label"] } == data["facility_label"] 
      	# Since our test now uses a syslog message, full and short message are the same.
      	insist { LogStash::Json.load(d)["full_message"] } == data["message"]
        insist { LogStash::Json.load(d)["short_message"] } == data["message"]
        got_event = true
      end
      subject.encode(event)
      insist { got_event }
    end
  end
end

classdef ELabData < handle
    
    properties(Access = public)
        Data
    end
    
    properties(Access = private)
        ElabServiceUrl = 'http://192.168.1.108:3030'
        ApiRoutes = struct( ...
            'get_session',        '/api/get/session/:session_key', ...
            'get_sessions',       '/api/get/sessions/:lastn?', ...
            'get_session_data',   '/api/get/session/data/:session_key/:convert_units?', ...
            'get_session_qr',     '/api/get/session/qr/:session_key' ...
            );
    end
    
    methods(Access = public)
        
        function obj = ELabData(session_key)
            obj.Data = obj.fetchApi('get_session_data',{':session_key',session_key,':convert_units?',1});
            obj.Data.time = datetime(obj.Data.timestamp, 'InputFormat', 'yyyy-MM-dd HH:mm:ss.SSSZ', 'TimeZone', ['UTC+' num2str(-java.util.Date().getTimezoneOffset()/60)]);
            obj.Data = rmfield(obj.Data,'timestamp');
        end
        
        function data = getData(obj)
            data = obj.Data;
        end
        
        function plot(obj,varargin)
            validCell = @(x) iscell(x);
            parser = inputParser;
            addOptional(parser,'fnames',fieldnames(obj.Data),validCell);
            parse(parser,varargin{:});
            param = parser.Results;
            fnames = param.fnames;
            if(length(fieldnames(obj.Data))~=length(fnames))
                len = length(fnames);
            else
                len = length(fnames)-1;
            end
            figure;
            cols = ceil(sqrt(len));
            rows = ceil(len/cols);
            for i=1:len
                subplot(cols,rows,i);
                plot(obj.Data.time, obj.Data.(fnames{i}).data);
                title(obj.Data.(fnames{i}).description);
                ylabel([strrep(fnames{i},'_','\_') ' [' obj.Data.(fnames{i}).unit ']']);
            end
        end
        
    end
    
    methods(Access=private)
        
        function output = fetchApi(obj, route, params)
            param_route = obj.fillParams(obj.ApiRoutes.(route), params);
            output = jsondecode(urlread([obj.ElabServiceUrl param_route]));
        end
        
    end
    
    methods(Static)
        
        function output = fillParams(param_route, params)
            for i = 1:2:length(params)
                param_route = strrep(param_route,params{i},num2str(params{i+1}));
            end
            output = param_route;
        end
        
    end
end


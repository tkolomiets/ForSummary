unit ArteIB.Integration;

interface

uses
  System.SysUtils, System.Classes, SyncObjs, System.Generics.Collections, ActiveX,
  Spring.Collections,
  ArteIB.Log.Types, ArteIB.Config, ArteIB.Entities.Utils, ArteIB.Constants, ArteIB.DBManager,
  ArteIB.Entities.Bus, ArteB.Classes,
  ArteIB.EventProcessor, ArteIB.RemoteSystem,
  Aurelius.Criteria.Linq, Arte.AU.Types;

type
  TISThread = class (TThreadLog)
   private
     fIntegrationId: TPrimaryKey;
     fRemoteSystem: TRemoteSystem;
     fRepo: TDBManager;
     fIntegrationParams: TDictionary<double, string>;
     fEventProcessors: TList<TEventProcessor>;
     fEventProcessorEvents: TDictionary<integer,TEventProcessor>;

     const ISStatusSource: string = 'Состояние СИ';

     procedure ProcessEvent(const AEvent: TIntegrationEvent);
     procedure LoadParams;
     procedure SetActive(AIsActive: boolean = True; AStatusInfo: string = '');
     function  GetEventProcessInfo(AProcessingEvent: TIntegrationEvent): string;
   protected
     property IntegrationId: TPrimaryKey read fIntegrationId;
     property Repo: TDBManager read fRepo;
     property RemoteSystem: TRemoteSystem read fRemoteSystem write fRemoteSystem;
     property IntegrationParams: TDictionary<double, string> read fIntegrationParams;

     property EventProcessors: TList<TEventProcessor> read fEventProcessors;
     property EventProcessorEvents: TDictionary<integer,TEventProcessor> read fEventProcessorEvents;

     function GetEventProcessor(AEvent: TIntegrationEvent): TEventProcessor;
     function IsEventSupported(AEvent: TIntegrationEvent): Boolean;

     procedure RegisterEventProcessor(const ARef: RefEventProcessor);

     procedure Initialize; virtual; abstract;
     procedure PreExecute; virtual;
     procedure PostExecute; virtual;

   public
     class function TypeId: TPrimaryKey; virtual; abstract;

     procedure Execute; override;

     constructor Create(AIntegrationId: TPrimaryKey);
     destructor Destroy; override;

     class procedure RegisterSelf;
  end;

  TISThreadRef = class of TISThread;

  IISCollection = IList<TISThreadRef>;

function ISCollection: IISCollection;

implementation

uses
  Generics.Defaults, System.StrUtils,
  ArteIB.Utils;

var
  vCollection: IISCollection;

function ISCollection: IISCollection;
begin
  if not Assigned(vCollection) then
    vCollection :=  TCollections.CreateList<TISThreadRef>;

  Result  :=  vCollection;
end;

constructor TISThread.Create(AIntegrationId: TPrimaryKey);
begin
 inherited Create;
 fRepo := TDBManager.Create();
 fIntegrationId := AIntegrationId;
 fIntegrationParams := TDictionary<double, string>.Create;

 fEventProcessors := TList<TEventProcessor>.Create;
 fEventProcessorEvents := TDictionary<integer,TEventProcessor>.Create;

 LoadParams;
 Initialize;
 LogInfo('Поток СИ создан.');
end;

destructor TISThread.Destroy;
var
 eventProcessor: TEventProcessor;
begin
  LogInfo('Поток СИ освобождается.');

  for eventProcessor in fEventProcessors do
    eventProcessor.Free;
  EventProcessors.Free;

  EventProcessorEvents.Free;
  RemoteSystem.Free;
  IntegrationParams.Free;
  Repo.Free;

  LogInfo('Поток СИ освобожден.');

  inherited;
end;

procedure TISThread.ProcessEvent(const AEvent: TIntegrationEvent);
var
  eventProcessor: TEventProcessor;
  processResult: TEventProcessResult;
  statusInfo: string;
begin
  LogInfoFmt('Обрабатывается событие [%s, %d, %d]', [AEvent.Type_.Title, AEvent.Id, AEvent.EntityId]);

  processResult := nil;
  statusInfo := '';

  try
    try
      eventProcessor := GetEventProcessor(AEvent);

      if Assigned(eventProcessor) then
        processResult := eventProcessor.ProcessEvent(AEvent)
      else
        LogWarning('Не найден обработчик события.');

      if (Not Assigned(processResult)) or (processResult.EventStatusInfo = '') then begin
        AEvent.Status := GetEventProcessStatusSuccess(Repo);
        LogInfo(GetEventProcessInfo(AEvent));
      end
      else
      begin
        statusInfo := processResult.EventStatusInfo;

        if Not Assigned(processResult.EventStatus) then
          AEvent.Status := GetEventProcessStatusWarning(Repo)
        else
          AEvent.Status := processResult.EventStatus;

        LogWarning(GetEventProcessInfo(AEvent), statusInfo);
      end;
    except
      on E: Exception do begin
        AEvent.Status := GetEventProcessStatusFailed(Repo);
        statusInfo := E.Message;
        LogError(GetEventProcessInfo(AEvent), E);
      end;
    end; // try process event
  finally
    AEvent.StatusTime := Now;
    AEvent.StatusInfo := statusInfo;
    Repo.Flush(AEvent);

    if Assigned(processResult) then
      processResult.Free;
  end;
end;

procedure TISThread.SetActive(AIsActive: boolean = True; AStatusInfo: string = '');
var
  integration: TIntegration;
begin
  integration := Repo.Get<TIntegration>(IntegrationId);

  integration.IsActive := AIsActive;
  integration.StatusTime := Now;
  integration.StatusInfo := AStatusInfo;

  Repo.Flush(integration);
  LogInfo(Format('СИ [%s] перешел в статус [%s].', [integration.Type_.Title, ifThen(AIsActive, 'Активный', 'Неактивный')]), ISStatusSource, Repo);
end;

function TISThread.GetEventProcessInfo(AProcessingEvent: TIntegrationEvent): string;
var
  status: string;
begin
  status := '';

  case AProcessingEvent.Status.Id of
     epsSuccess:
       status := 'обработано успешно';
     epsErrorsWarnings:
       status := 'обработано c ошибками/предупреждениями';
     epsFailed:
       status := 'не обработано из-за ошибок';

  end;

  if status <> '' then
    Result := Format(
      'Событие %s [%s, %d, %d]',
      [status, AProcessingEvent.Type_.Title, AProcessingEvent.Id, AProcessingEvent.EntityId]
    )
  else
    Result := '';
end;

procedure  TISThread.LoadParams;
var
  vInt: TIntegration;
  vIP: TIntegrationParam;
  vValue: string;
begin
  // Create empty list of needed params in child integration class,
  // based on params types IDs (see Constants.pas)
  vInt := Repo.Get<TIntegration>(IntegrationId);

  LogInfo('ПАРАМЕТРЫ ИНТЕГРАЦИИ:');

  // Set child's needed params by values
  for vIP in vInt.Params do begin
    vValue  :=  vIP.Value.Trim;

    IntegrationParams.AddOrSetValue(vIP.TP.ParamType.Id, vValue);
    LogInfoFmt('%s (%s) = %s', [vIP.TP.ParamType.Title, vIP.TP.Description, vValue]);
  end;
end;

procedure TISThread.RegisterEventProcessor(const ARef: RefEventProcessor);
var
  vEventProcessor: TEventProcessor;
  vEvents: TArray<TPrimaryKey>;
  vEventType: integer;
begin
  Assert(Assigned(ARef));

  vEventProcessor :=  ARef.Create(IntegrationId, Repo, RemoteSystem, IntegrationParams);
  EventProcessors.Add(vEventProcessor);

  vEvents :=  vEventProcessor.GetProcessingEvents;
  for vEventType in vEvents do
    if Not EventProcessorEvents.ContainsKey(vEventType) then
      EventProcessorEvents.Add(vEventType, vEventProcessor)
    else
      raise Exception.CreateFmt('Дублирование подписки на событие [%d] в процессоре [%s].',
                   [vEventType, vEventProcessor.ClassName]);
end;

class procedure TISThread.RegisterSelf;
begin
  ISCollection.Add(Self);
end;

function  TISThread.IsEventSupported(AEvent: TIntegrationEvent): Boolean;
var
  eventType: integer;
begin
  Result := False;

  for eventType in EventProcessorEvents.Keys do
    if (eventType = AEvent.Type_.Id) then
    begin
      Result := true;
      break;
    end;
end;

function TISThread.GetEventProcessor(AEvent: TIntegrationEvent): TEventProcessor;
begin
  if not EventProcessorEvents.TryGetValue(AEvent.Type_.Id, Result) then
    Result := nil;
end;

procedure TISThread.Execute;
var
  processingEventList: TList<TIntegrationEvent>;
  processingEvent: TIntegrationEvent;
  sleepWorkCicle: integer;
  eventsPerTime: integer;
  threadError: string;
begin
  CoInitialize(nil);

  try
    try
      PreExecute;

      sleepWorkCicle := StrToInt(SystemSettings.GetSettingValue(['common','sleep_work_cicle'],'5000'));
      eventsPerTime := StrToInt(SystemSettings.GetSettingValue(['common','events_per_time'],'1000'));

      threadError := '';

      SetActive;

      LogInfoFmt('Старт рабочего цикла потока СИ [sleep = %d msec]', [sleepWorkCicle]);

      while not Terminated do
      begin

        Sleep(sleepWorkCicle);

        processingEventList :=
          Repo.Find<TIntegrationEvent>()
          .CreateAlias('Integration', 'i')
          .Where(
            (Linq['i.Id'] = IntegrationId) And (Linq['Status'] = epsNew)
          )
          .OrderBy('Id')
          .Take(eventsPerTime)
          .List;

        try
          if processingEventList.Count > 0 then
            LogInfoFmt('Обрабатывается событий: %d',[processingEventList.Count]);

          for processingEvent in processingEventList do begin
            ProcessEvent(processingEvent);
          end; // for events loop

        finally
          processingEventList.Free;
          Repo.ClearCache;
        end; // try with events

      end; // while not terminated
    except
      on E: Exception do
      begin
        LogError('Ошибка в потоке СИ. Поток будет остановлен.', E);
        threadError := E.Message;
      end;
    end;

  finally
    PostExecute;
    CoUninitialize;
  end;

  try
    SetActive(False, threadError);
  except
    on E: Exception do
      LogError('Не удалось сохранить в базе данных финальное состояние потока СИ.', E);
  end;

  LogInfo('Поток СИ завершил работу.');
end;

procedure TISThread.PreExecute;
begin
  ;
end;

procedure TISThread.PostExecute;
begin
  ;
end;

end.
